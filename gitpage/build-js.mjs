import { readFileSync, writeFileSync } from "node:fs";
import { transform } from "esbuild";

const files = [
  "parts/primitives.jsx",
  "parts/background.jsx",
  "parts/header.jsx",
  "parts/hero.jsx",
  "parts/sections-a.jsx",
  "parts/sections-b.jsx",
  "parts/sections-c.jsx",
  "parts/footer-cta.jsx",
  "app.jsx",
];

const source = files
  .map((file) => `\n/* ${file} */\n${readFileSync(file, "utf8")}`)
  .join("\n");

const result = await transform(source, {
  loader: "jsx",
  jsx: "transform",
  jsxFactory: "React.createElement",
  jsxFragment: "React.Fragment",
  minify: true,
  target: "es2019",
  legalComments: "none",
});

writeFileSync("bundle.js", `${result.code}\n`);

const css = ["tailwind.css", "styles.css"]
  .map((file) => `\n/* ${file} */\n${readFileSync(file, "utf8")}`)
  .join("\n");

const cssResult = await transform(css, {
  loader: "css",
  minify: true,
  target: "es2019",
  legalComments: "none",
});

writeFileSync("site.css", `${cssResult.code}\n`);
