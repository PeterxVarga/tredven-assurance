import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {readFileSync} from 'node:fs';
const spec=JSON.parse(readFileSync('/input/replay.json','utf8'));
const client=new Client({name:'tredven-assurance-replay',version:'1.0.0'});
try{
 await client.connect(new StdioClientTransport({command:'/opt/node',args:[process.argv[2]],cwd:'/server',env:{PATH:'/opt:/usr/bin',HOME:'/tmp'}}));
 const result=await client.callTool({name:spec.tool,arguments:spec.arguments});
 console.log(JSON.stringify({match:result.isError!==true && JSON.stringify(result.content)===JSON.stringify(spec.expected_content),isError:result.isError===true}));
}finally{await client.close();}
