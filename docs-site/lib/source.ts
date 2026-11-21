import { llms, loader } from 'fumadocs-core/source';
import { lucideIconsPlugin } from 'fumadocs-core/source/lucide-icons';
import { docsRoute } from './shared';
import { defineDocs } from 'fumadocs-mdx/macro';
import { metaSchema, pageSchema } from 'fumadocs-core/source/schema';
import { openapi } from './openapi';

const docs = defineDocs({
  dir: 'content/docs',
  docs: {
    schema: pageSchema,
    postprocess: {
      includeProcessedMarkdown: true,
    },
  },
  meta: {
    schema: metaSchema,
  },
});

// Named sources: the docs site's MDX pages plus virtual pages generated from
// Signet's OpenAPI contract. See https://fumadocs.dev/docs/headless/source-api
export const source = loader(
  {
    docs: docs.toFumadocsSource(),
    openapi: await openapi.staticSource({ baseDir: 'openapi' }),
  },
  {
    baseUrl: docsRoute,
    plugins: [lucideIconsPlugin(), openapi.loaderPlugin()],
  },
);

export const docsLlms = llms(source, {
  renderPage: async (page) => {
    if (page.type === 'openapi') {
      return `# ${page.data.title} (${page.url})\n\n${JSON.stringify(page.data.getSchema().bundled, null, 2)}`;
    }
    return `# ${page.data.title} (${page.url})\n\n${await page.data.getText('processed')}`;
  },
});
