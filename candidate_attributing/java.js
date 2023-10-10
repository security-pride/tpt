Java.perform(() => {
    const searchString = $searchString;

    const Exception = Java.use('java.lang.Exception');
    const Log = Java.use('android.util.Log');

    var targetClass='java.io.File';
	var methodName='$init';
	var gclass = Java.use(targetClass);
	gclass[methodName].overload('java.lang.String').implementation = function(arg0) {
        if (arg0.search(searchString) != -1){
            console.log('\n[Hook $init(java.lang.String)]'+'\n\targ0 = '+arg0);
		    var i=this[methodName](arg0);
		    console.log('\treturn '+i);
            console.log(stackTraceHere())
		    return i;
        } else {
            var i=this[methodName](arg0);
		    return i;
        }
	}

    var targetClass1='java.io.File';
	var methodName1='$init';
	var gclass1 = Java.use(targetClass1);
	gclass1[methodName1].overload('java.lang.String','java.lang.String').implementation = function(arg0,arg1) {
        if (arg0.search(searchString) != -1 || arg1.search(searchString) != -1){
            console.log('\n[Hook $init(java.lang.String,java.lang.String)]'+'\n\targ0 = '+arg0+'\n\targ1 = '+arg1);
            var i=this[methodName1](arg0,arg1);
            console.log('\treturn '+i);
            console.log(stackTraceHere())
            return i;
        } else {
            var i=this[methodName1](arg0,arg1);
            return i;
        }
	}

    var targetClass2='java.io.File';
	var methodName2='$init';
	var gclass2 = Java.use(targetClass2);
	gclass2[methodName2].overload('java.io.File','java.lang.String').implementation = function(arg0,arg1) {
        if (arg1.search(searchString) != -1){
            console.log('\n[Hook $init(java.io.File,java.lang.String)]'+'\n\targ0 = '+arg0+'\n\targ1 = '+arg1);
            var i=this[methodName2](arg0,arg1);
            console.log('\treturn '+i);
            console.log(stackTraceHere())
            return i;
        } else {
            var i=this[methodName2](arg0,arg1);
            return i;
        }
	}


    function stackTraceHere() {
      return Log.getStackTraceString(Exception.$new());
    }
});