var searchString = $searchString;

Interceptor.attach(Module.findExportByName("libc.so" , "open"), {
    onEnter: function(args) {
        var filenameRaw = new Uint8Array(Memory.readByteArray(args[0],80));
        var filename = uint8ArrayToString(filenameRaw);
        if (filename.search(searchString) != -1) {
            console.log("open called! args[0]:" + filename);
            print_c_stack(this.context, "open")
        }
    },
    onLeave:function(retval){

    }
});

function print_c_stack(context, str_tag)
{
    console.log('\n');
    console.log("=============================" + str_tag + " Stack strat=======================");
    console.log(Thread.backtrace(context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'));
    console.log("=============================" + str_tag + " Stack end  =======================");

}

function uint8ArrayToString(u8a) {
	var dataStr = "";
	for(var i=0;i<u8a.length;i++) {
		dataStr += String.fromCharCode(u8a[i])
	}
	return dataStr;
}