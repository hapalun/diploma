var fs = require('fs');
var falafel = require('falafel');

var filename = process.argv[2];

var vector = '<script>alert();<\/script>';
var sources = [];

var code = fs.readFileSync(filename) + '';

code = falafel(code, function(node){


  //Array of variables containing XSS-vector

  if (node.type === 'VariableDeclarator' && node.init.value === vector){
      sources.push(node.id.name);
      //node.update(node.source() + ';\nsources.push(\'' + node.id.name + '\')');
  }

  //Instrument code

  if (node.type === 'Program'){
  node.update('<script>\nvar route = [];\n' + node.source() + '\nconsole.log(route.join(\' \'));\n<\/script>')
  }
  for (var i=0; i < sources.length; i++){

    if (node.type === 'ExpressionStatement' && node.expression.arguments) {
        for (var j=0; j < node.expression.arguments.length; j++){
        if (node.expression.arguments[j].name === sources[i] || node.expression.arguments[j].value === vector){
            if (node.expression.type === 'CallExpression'){
                if (node.expression.callee.name) {
                    node.update('try {\n' + node.source() + '\nroute.push(\'' + node.expression.callee.name + '\');' + '\n} catch(err){}');
                }
            }
            if (node.expression.callee.type === 'MemberExpression'){
                node.update('try {\n' + node.source() + '\nroute.push(\'' + node.expression.callee.object.name + '.' + node.expression.callee.property.name + '\');' + '\n} catch(err){}');
                }
        }
        }
    }

    try{
    if (node.type === 'CallExpression') {
        for (var i=0; i < sources.length; i++){
            if (node.callee.object.name === sources[i]) {
                node.parent.update('try {\n' + node.parent.source() + '\nroute.push(\'' + sources[i] + '.' + node.callee.property.name + '\');' + '\n} catch(err){}')
            }
        }
    }
    } catch (err){}

    if (node.type === 'VariableDeclaration') {
      for (var k=0; k<node.declarations.length; k++) {
        if (node.declarations[k].init.arguments){
        for (var j=0; j < node.declarations[k].init.arguments.length; j++){

                if (node.declarations[k].init.arguments[j].name === sources[i] || node.declarations[k].init.arguments[j].value === vector){
                    node.update('try {\n' + node.source() + '\nroute.push(\'' + node.declarations[k].init.callee.name + '\');' + '\n} catch(err){}');
                }
        }
        }
      }
      }
  }

  //new Function


});

//console.log(code);
//console.log(sources.join(' '));

fs.writeFile(process.argv[3], code, console.log('code instrumented!'));