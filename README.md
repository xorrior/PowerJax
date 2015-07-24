# PowerJax
Shellcode Injection with Powershell. 

Power Jax

Power Jax re-introduces a very very old concept, shellcode injection. In order to access the Windows API calls necessary for shellcode
injection in Powershell, code from Matt Graeber's PSReflect module (https://github.com/mattifestation/PSReflect) is used. Currently, a major limitation of shellcode injection via PowerShell is
that you may only inject shellcode into a process of the same architecture as the current PowerShell process.

The script only takes the process ID for remote shellcode injection. There is a 32 bit and 64 bit version of the shellcode that will be 
used in the script. Please change it to whatever you desire, as it only opens calc.exe . 

#Examples

Invoke-PowerJax

Inject the contained shellcode into the current powershell process. 

Invoke-PowerJax 1344

Inject the contained shellcode into the remote process. 
