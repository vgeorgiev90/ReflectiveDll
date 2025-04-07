### Reflective DLL 

Simple reflective DLL project in visual studio. Its making use of hashes libraries and functions to resolve all the required APIs for the reflective loader.
It has one exported function called `Load` that is responsible for:
 - Resolving the DLL base address 
 - Dynamically resolve the APIs that will be used for reflective loading
 - Parsing the PE headers and saving required ones for later usage
 - Allocating a new RW memory block and copying all of the PE's sections
 - Fixing the Address Import Table
 - Applying the base relocations
 - Calling the DLLMain

The DllMain is calling another function called `Runner` that is delivering the actual payload. At the moment a simple registry based persistence is included as a PoC. 
Three helpers functions are used as a replacement for `GetModuleHandle`, `GetProcAddress` and `LoadLibraryA`.



TODO:
- Possibly check if the DLL is being injected or simply run via rundll32 for example.



USAGE:

Simply compile the project and inject the reflective DLL in a target process. Stephen Fewer's original [inject](https://github.com/stephenfewer/ReflectiveDLLInjection/tree/master/inject) tool was used for testing.
But any other capable loader should do. For resolving the dll's base address [Cracked5pider's `KaynCaller`](https://github.com/HavocFramework/Modules/blob/main/Template/src/Util.s) function was reused.
If you want to make changes to the assembly code, just recompile it with `nasm` and include it in the project.

