import { build } from "esbuild";
import { cp, mkdir, rm } from "node:fs/promises";

await rm("dist", { recursive: true, force: true });
await mkdir("dist", { recursive: true });
await cp("index.html", "dist/index.html");
await cp("styles.css", "dist/styles.css");
await cp("assets", "dist/assets", { recursive: true });
await build({
  entryPoints: ["main.js"],
  bundle: true,
  format: "esm",
  target: ["es2022"],
  outfile: "dist/main.js",
  sourcemap: false,
  minify: true,
});
