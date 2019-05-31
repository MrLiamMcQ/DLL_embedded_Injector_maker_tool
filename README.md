# DLL_embedded_Injector_maker_tool
drag and drop dll on window and makes a injector with the embedded dll you dragged onto it.

Instructions to complie it:

1. compile Injector project on release on 32 bit then 64 bit
2. compile the embedingCode on release on 32 bit
3. compile the DllEmbeddedInjectorMaker how every you want should work fine.

Instructions on usage:

1. open "DllEmbeddedInjectorMaker.exe"
2. input your target exe for injecting into, into the field called "Target exe for injector"
3. make sure your target exe has the same architecture as your dll
4. drag and drop your dll you want injecting onto any white space
5. a file should now be created called "InjectorWithInbeddedDLL.exe"
6. run this new file, it should inject the dll you draged onto the main program into the traget dll
