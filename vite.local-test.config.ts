/**
 * Separate localhost-only browser integration config. NOT used by npm run
 * build, which uses vite.config.ts and the public index.html.
 */
import {defineConfig} from "vite";
import react from "@vitejs/plugin-react";
export default defineConfig({
  plugins:[react()],
  publicDir:false,
  server:{
    host:"127.0.0.1",port:5176,strictPort:true,
    headers:{"cache-control":"no-store","x-robots-tag":"noindex, nofollow"},
    proxy:{
      "/__local_protocol__":{
        target:"http://127.0.0.1:18880",
        changeOrigin:false
      }
    }
  }
});
