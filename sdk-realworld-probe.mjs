// Original, harmless reproductions of documented public SDK issues. No external I/O.
const before=globalThis.fetch;
const types=await import('@modelcontextprotocol/sdk/types.js');
const {McpServer}=await import('@modelcontextprotocol/sdk/server/mcp.js');
const {Client}=await import('@modelcontextprotocol/sdk/client/index.js');
const {InMemoryTransport}=await import('@modelcontextprotocol/sdk/inMemory.js');
const {z}=await import('zod');
const out={};
async function test(id,fn){try{out[id]=await fn()}catch(e){out[id]={pass:false,error:String(e.message).slice(0,240)}}}
const make=()=>new McpServer({name:'qualification',version:'1.0.0'});
async function connect(s,fn){const [a,b]=InMemoryTransport.createLinkedPair();const c=new Client({name:'qualification',version:'1.0.0'});try{await s.connect(a);await c.connect(b);return await fn(c)}finally{await c.close();await s.close()}}
const ret=()=>({content:[{type:'text',text:'ok'}]});
await test('1302',()=>({pass:['isJSONRPCResponse','isJSONRPCError','isJSONRPCRequest'].every(k=>typeof types[k]==='function'),exports:['isJSONRPCResponse','isJSONRPCError','isJSONRPCRequest'].map(k=>typeof types[k])}));
await test('1376',()=>({pass:before===globalThis.fetch}));
await test('1960',async()=>{const s=make();const schema=z.object({id:z.string()}).passthrough();const t=s.registerTool('sample',{inputSchema:schema},ret);t.update({paramsSchema:schema});return await connect(s,async c=>({pass:!!(await c.listTools()).tools[0].inputSchema.properties.id}))});
await test('1869',async()=>{const s=make();s.registerPrompt('sample',{argsSchema:{context:z.string().optional()}},a=>({messages:[{role:'user',content:{type:'text',text:a.context??'none'}}]}));return await connect(s,async c=>{let omitted=false;try{omitted=(await c.getPrompt({name:'sample'})).messages[0].content.text==='none'}catch{}let explicit=false;try{explicit=(await c.getPrompt({name:'sample',arguments:{}})).messages[0].content.text==='none'}catch{}return {pass:omitted,explicit_empty_workaround:explicit}})});
await test('1956',async()=>{const s=make();s.registerTool('sample',{inputSchema:{id:z.string()}},ret);return await connect(s,async c=>{try{const r=await c.callTool({name:'sample',arguments:{id:123}});return {pass:r.isError===true,mode:'tool-result'}}catch(e){return {pass:false,mode:'protocol-error',code:e.code}}})});
await test('2084',async()=>{const s=make();s.registerTool('sample',{inputSchema:{id:z.string()},outputSchema:{id:z.string()}},()=>({...ret(),structuredContent:{id:'ok'}}));return await connect(s,async c=>{const t=(await c.listTools()).tools[0];return {pass:t.inputSchema.$schema==='https://json-schema.org/draft/2020-12/schema'&&t.outputSchema.$schema==='https://json-schema.org/draft/2020-12/schema',input:t.inputSchema.$schema??null,output:t.outputSchema.$schema??null}})});
await test('2636',async()=>{const s=make();s.registerTool('sample',{inputSchema:{id:z.string()}},ret);return await connect(s,async c=>{const a=(await c.listTools()).tools[0].inputSchema;return {pass:a.additionalProperties===false,additionalProperties:a.additionalProperties??null}})});
await test('2464',async()=>{const s=make();s.registerTool('sample',{inputSchema:{id:z.string()},outputSchema:{date:z.date()}},()=>({...ret(),structuredContent:{date:new Date(0)}}));return await connect(s,async c=>({pass:!!(await c.listTools()).tools[0].outputSchema?.properties?.date}))});
await test('2627',async()=>{const s=make();s.registerTool('sample',{inputSchema:z.object({id:z.string()})},ret);return await connect(s,async c=>({pass:!!(await c.listTools()).tools[0].inputSchema.properties?.id}))});
await test('1864',async()=>{const s=make();s.registerTool('sample',{icons:[{src:'https://example.invalid/icon.png',mimeType:'image/png'}]},ret);return await connect(s,async c=>({pass:(await c.listTools()).tools[0].icons?.length===1}))});
console.log(JSON.stringify(out));
