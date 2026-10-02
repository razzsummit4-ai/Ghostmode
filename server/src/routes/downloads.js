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

/** Lowest Android this build runs on. Below this the installer refuses it. */
export const MIN_ANDROID = '7.0 (API 24)';

export const DOWNLOADS = [
  {
    file: 'SecureChat-arm64-v8a.apk',
    label: 'Modern phone (64-bit)',
    hint: 'Most phones from 2017 onward. Smallest download.',
    size: '19 MB',
    bytes: 19989866,
  },
  {
    file: 'SecureChat-armeabi-v7a.apk',
    label: 'Older phone (32-bit)',
    hint: 'Required if the 64-bit build will not install - many phones before 2017 are 32-bit.',
    size: '17 MB',
    bytes: 17414966,
  },
  {
    file: 'SecureChat-1.0.0.apk',
    label: 'Universal - works on every device',
    hint: 'Contains all CPU types. Use this if you are unsure, or if the others fail.',
    size: '53 MB',
    bytes: 55684048,
  },
  {
    file: 'SecureChat-x86_64.apk',
    label: 'Emulator only',
    hint: 'For an Android emulator on a computer, not for a real phone.',
    size: '20 MB',
    bytes: 21408102,
  },
];