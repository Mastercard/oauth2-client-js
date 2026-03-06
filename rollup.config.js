import typescript from '@rollup/plugin-typescript';
import { nodeResolve } from '@rollup/plugin-node-resolve';
import terser from '@rollup/plugin-terser';
import replace from '@rollup/plugin-replace';

const createConfig = (input, output, format, options = {}) => ({
  input,
  output: {
    file: output,
    format,
    sourcemap: !options.minify,
    exports: 'named',
    inlineDynamicImports: true,
    ...(options.name && { name: options.name }),
    ...(options.globals && { globals: options.globals })
  },
  plugins: [
    replace({
      preventAssignment: true,
      values: {
        'process.env.npm_package_version': JSON.stringify(process.env.npm_package_version)
      }
    }),
    nodeResolve({ preferBuiltins: false }),
    typescript({
      tsconfig: './tsconfig.build.json',
      target: 'ES2020',
      module: 'ESNext',
      declaration: !options.minify,
      declarationMap: !options.minify,
      sourceMap: !options.minify,
      inlineSources: !options.minify,
      outDir: 'dist'
    }),
    ...(options.minify ? [terser({
      compress: {
        drop_console: false,
        drop_debugger: true
      },
      format: {
        comments: false
      }
    })] : [])
  ],
  external: options.bundleAll ? [] : ['axios', 'superagent']
});

export default [
  createConfig('src/index.ts', 'dist/index.cjs', 'cjs'),
  createConfig('src/index.ts', 'dist/index.esm.js', 'es'),
  createConfig('src/http/integrations/axios.ts', 'dist/axios.cjs', 'cjs'),
  createConfig('src/http/integrations/axios.ts', 'dist/axios.esm.js', 'es'),
  createConfig('src/http/integrations/superagent.ts', 'dist/superagent.cjs', 'cjs'),
  createConfig('src/http/integrations/superagent.ts', 'dist/superagent.esm.js', 'es'),
  createConfig('src/index.ts', 'dist/index.umd.min.js', 'umd', {
    name: 'MastercardOAuth2Client',
    minify: true,
    bundleAll: false,
    globals: {
      'axios': 'axios',
      'superagent': 'superagent'
    }
  })
];
