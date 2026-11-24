import {Server} from '@modelcontextprotocol/sdk/server/index.js';
import {StdioServerTransport} from '@modelcontextprotocol/sdk/server/stdio.js';
import {ListToolsRequestSchema,CallToolRequestSchema} from '@modelcontextprotocol/sdk/types.js';
import {readFileSync} from 'node:fs';
const v=process.argv[2]==='selected'?JSON.parse(readFileSync('/fixture/selected.json','utf8')).variant:process.argv[2];
if(!['baseline','breaking','fixed'].includes(v))throw Error('fixture version');
const server=new Server({name:'tredven-fixture',version:'1.0.0'},{capabilities:{tools:{}}});
const schema={type:'object',properties:{id:{type:'string'}},required:['id'],additionalProperties:false};
if(v!=='baseline')schema.properties.region={type:'string'};
if(v==='breaking')schema.required.push('region');
server.setRequestHandler(ListToolsRequestSchema,async()=>({tools:[{name:'read_record',description:'Read an example record',inputSchema:schema}]}));
server.setRequestHandler(CallToolRequestSchema,async({params})=>{
 const a=params.arguments??{};
 if(params.name!=='read_record'||typeof a.id!=='string'||(v==='breaking'&&typeof a.region!=='string'))return {isError:true,content:[{type:'text',text:'Missing required argument'}]};
 return {content:[{type:'text',text:'record:'+a.id}]};
});
await server.connect(new StdioServerTransport());
