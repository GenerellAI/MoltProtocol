import { defineConfig } from 'astro/config';
import mdx from '@astrojs/mdx';

export default defineConfig({
  site: 'https://moltprotocol.org',
  integrations: [mdx()],
  output: 'static',
});
