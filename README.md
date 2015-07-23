# PowerJax
Shellcode Injection with Powershell. (Cross-Arch Coming soon)

Power Jax

Power Jax re-introduces a very very old concept, shellcode injection. In order to access the Windows API calls necessary for shellcode
injection in Powershell, code from Matt Graeber's PSReflect module is used. Currently, a major limitation of shellcode injection is
that you may only inject shellcode into a process of the same architecture as powershell. In the near future, I hope to remove that
limitation. For more information on how that's possible, look here: https://disman.tl/2015/03/16/cross-architecture-reflective-dll-inection.html

The script only takes the process ID for remote shellcode injection. There is a 32 bit and 64 bit version of the shellcode that will be 
used in the script. Please change it to whatever you desire, as it only opens calc.exe . 

Example

Invoke-PowerJax

#Inject the contained shellcode into the current powershell process. 

Invoke-PowerJax 1344

#Inject the contained shellcode into the remote process. 
