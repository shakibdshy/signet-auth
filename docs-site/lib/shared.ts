import { createGetUrl } from 'fumadocs-core/source';

export const appName = 'Signet';
export const docsRoute = '/docs';
export const docsImageRoute = '/og/docs';

// GitHub coordinates for "view on GitHub" links in the docs.
export const gitConfig = {
  user: 'shakibdshy',
  repo: 'signet',
  branch: 'main',
};

const getImageUrl = createGetUrl(docsImageRoute);

export function getPageImageUrl(page: { slugs: string[]; locale?: string }) {
  const segments = [...page.slugs, 'image.png'];

  return { segments, url: getImageUrl(segments, page.locale) };
}
