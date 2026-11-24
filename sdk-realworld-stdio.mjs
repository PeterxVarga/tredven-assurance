import {McpServer} from '@modelcontextprotocol/sdk/server/mcp.js';
import {StdioServerTransport} from '@modelcontextprotocol/sdk/server/stdio.js';
import {z} from 'zod';
const s=new McpServer({name:'sdk-date-repro',version:'1.0.0'});
s.registerTool('read_record',{description:'Read a fixture record',inputSchema:{id:z.string()},outputSchema:{date:z.date()}},()=>({content:[{type:'text',text:'record:test'}],structuredContent:{date:new Date(0)}}));
await s.connect(new StdioServerTransport());
