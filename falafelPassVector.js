var fs = require('fs');
var falafel = require('falafel');

var filename = process.argv[2];

var vector = '<script>alert();<\\/script>';
var src1 = ['referrer','URL','documentURI','cookie','name','getElementById','href','search','pathname','hash'];

var code = fs.readFileSync(filename) + '';

code = falafel(code, function(node){

  //Pass XSS-vector to source

  if (node.type === 'ExpressionStatement'){
  if (node.expression.arguments){
  for (var k=0; k < node.expression.arguments.length; k++){
    try{
        if ((node.expression.arguments[k].object.name === 'document' || node.expression.arguments[k].object.name === 'window') && (src1.indexOf(node.expression.arguments[k].property.name)>-1)){
            node.expression.arguments[k].update('\'' + vector + '\'');
        }
    } catch(err){};
    try{
        if ((node.expression.arguments[k].object.object.name === 'document' || node.expression.arguments[k].object.object.name === 'window') && (node.expression.arguments[k].object.property.name === 'location') && (src1.indexOf(node.expression.arguments[k].property.name)>-1)){
            node.expression.arguments[k].update('\'' + vector + '\'');
        }
    } catch(err){};
    }
    }

  try{
      if ((node.expression.right.callee.object.name === 'document' || node.expression.right.callee.object.name === 'window') && (src1.indexOf(node.expression.right.callee.property.name)>-1)){
          node.expression.right.update('\'' + vector + '\'');
      }
      } catch(err){};
  try{
        if ((node.expression.right.object.name === 'document' || node.expression.right.object.name === 'window') && (src1.indexOf(node.expression.right.property.name)>-1)){
            node.expression.right.update('\'' + vector + '\'');
        }
        } catch(err){};
  try{
      if ((node.expression.right.object.object.name === 'document' || node.expression.right.object.object.name === 'window') && (node.expression.right.object.property.name === 'location') && (src1.indexOf(node.expression.right.property.name)>-1)){
          node.expression.right.update('\'' + vector + '\'');
      }
    } catch(err){};
  }


  if (node.type === 'VariableDeclaration') {
    for (var i=0; i<node.declarations.length; i++) {

      try {
          if ((node.declarations[i].init.object.name === 'document'|| node.declarations[i].init.object.name === 'window') && (src1.indexOf(node.declarations[i].init.property.name)>-1)){
              node.declarations[i].init.update('\'' + vector + '\'');
          }
      } catch(err) {}
      try{
          if ((node.declarations[i].init.object.object.name === 'document' || node.declarations[i].init.object.object.name === 'window') && (node.declarations[i].init.object.property.name === 'location') && (src1.indexOf(node.declarations[i].init.property.name)>-1)){
              node.declarations[i].init.update('\'' + vector + '\'');
          }
      } catch(err){};
    }
  }
});
//console.log(code);
//console.log(sources.join(' '));

fs.writeFile(process.argv[3], code, console.log('done!'));