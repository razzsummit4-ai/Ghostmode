/**
 * The installable builds this server will hand out.
 *
 * Kept in one module so the landing page and the /download route can never
 * disagree about what exists. `file` must match the release asset name exactly,
 * because it is both the GitHub asset name and the name written into the
 * Content-Disposition header the phone saves the file under. `bytes` is the
 * verified size, sent as Content-Length so a phone shows real progress and can
 * detect a truncated transfer.
 *
 * Bump RELEASE_TAG when cutting a new build, or the server keeps serving the
 * old binaries.
 */
export const RELEASE_TAG = 'v1.0.0';

export const DOWNLOADS = [
  {
    file: 'SecureChat-arm64-v8a.apk',
    label: 'Download for most phones',
    size: '19 MB',
    bytes: 19989562,
  },
  {
    file: 'SecureChat-1.0.0.apk',
    label: 'Universal (any device)',
    size: '53 MB',
    bytes: 55683744,
  },
];