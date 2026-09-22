/* Authored for the AmbisGIS NO-JPEG2000 Java/server candidate, 2026.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.geoserver.filters;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.LinkOption;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Stream;
import java.util.zip.ZipFile;
import java.util.zip.ZipEntry;

/** Candidate capability policy; this class never decodes or converts an image. */
public final class NoJpeg2000Policy {
    public static final String MESSAGE =
            "JPEG2000 is unsupported in the AmbisGIS NO-JPEG2000 Java/server profile.";
    public static final long MAX_ARCHIVE_BYTES = 1024L * 1024 * 1024;
    public static final int MAX_ARCHIVE_MEMBERS = 10000;
    public static final String LIMIT_MESSAGE = "ZIP upload exceeds the NO-JPEG2000 profile limit (1 GiB compressed or 10000 members).";
    public static final class InputLimit extends IOException {
        private static final long serialVersionUID = 1L;
        public InputLimit() { super(LIMIT_MESSAGE); }
    }
    private static final Set<String> FORMATS = Set.of(
            "jp2", "j2k", "j2c", "jpc", "jpf", "jpx", "jpm", "mj2", "jpeg2000");
    private NoJpeg2000Policy() {}

    public static boolean format(String value) {
        if (value == null) return false;
        String name = value.split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
        if (name.startsWith("image/")) name = name.substring(6);
        if (name.startsWith("x-")) name = name.substring(2);
        return FORMATS.contains(name.replace(" ", "").replace("-", "").replace("_", ""));
    }

    public static boolean filename(String value) {
        if (value == null) return false;
        int dot = value.lastIndexOf('.');
        return dot >= 0 && format(value.substring(dot + 1));
    }

    /** Recognizable JPEG2000 magic, including truncated JP2/SOC input. Ordinary JPEG differs. */
    public static boolean signature(byte[] value) {
        return value.length >= 2 && (value[0] & 255) == 255 && (value[1] & 255) == 79
                || value.length >= 8 && value[0] == 0 && value[1] == 0 && value[2] == 0 && value[3] == 12
                && value[4] == 106 && value[5] == 80 && value[6] == 32 && value[7] == 32;
    }

    public static boolean zipSignature(byte[] value) {
        return value.length >= 4 && value[0] == 80 && value[1] == 75
                && ((value[2] == 3 && value[3] == 4) || (value[2] == 5 && value[3] == 6));
    }

    /** Random-access ZIP preflight: at most twelve decompressed bytes per member.
     * No member is extracted; ordinary large image data is not decompressed here.
     */
    public static boolean archive(Path path) throws IOException {
        if (Files.size(path) > MAX_ARCHIVE_BYTES) throw new InputLimit();
        try (ZipFile zip = new ZipFile(path.toFile())) {
            var entries = zip.entries();
            int count = 0;
            while (entries.hasMoreElements()) {
                if (++count > MAX_ARCHIVE_MEMBERS) throw new InputLimit();
                ZipEntry entry = entries.nextElement();
                if (entry.isDirectory()) continue;
                if (filename(entry.getName())) return true;
                try (InputStream input = zip.getInputStream(entry)) {
                    if (signature(input.readNBytes(12))) return true;
                }
            }
        }
        return false;
    }

    /** Copies at most 1 GiB to transient storage; callers own removal in every outcome. */
    public static void stageArchive(InputStream input, Path path) throws IOException {
        stageArchive(input, path, MAX_ARCHIVE_BYTES);
    }

    // Private limit injection allows a small actual copy-bound regression without
    // a runtime setting that could disable the selected production limit.
    private static void stageArchive(InputStream input, Path path, long maximum) throws IOException {
        try (java.io.OutputStream output = Files.newOutputStream(path)) {
            byte[] buffer = new byte[8192];
            long count = 0;
            int size;
            while ((size = input.read(buffer)) != -1) {
                if ((count += size) > maximum) throw new InputLimit();
                output.write(buffer, 0, size);
            }
        }
    }

    /** Compressed upload staging is transient and always removed before return. */
    public static boolean archive(InputStream input) throws IOException {
        Path staged = Files.createTempFile("AmbisgisCodecUpload", ".zip");
        try {
            stageArchive(input, staged);
            return archive(staged);
        } finally { Files.deleteIfExists(staged); }
    }

    public static boolean file(Path path) throws IOException {
        if (filename(path.getFileName().toString())) return true;
        try (InputStream input = Files.newInputStream(path)) { return signature(input.readNBytes(12)); }
    }

    /** Inspects only names and twelve signature bytes, without following directory symlinks. */
    public static boolean tree(Path path) throws IOException {
        if (Files.isSymbolicLink(path)) throw new IOException("Symbolic link is not a supported raster upload");
        if (!Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) return file(path);
        try (Stream<Path> files = Files.walk(path)) {
            var iterator = files.iterator();
            while (iterator.hasNext()) {
                Path item = iterator.next();
                if (Files.isSymbolicLink(item)) throw new IOException("Symbolic link is not a supported raster upload");
                if (Files.isRegularFile(item, LinkOption.NOFOLLOW_LINKS) && file(item)) return true;
            }
        }
        return false;
    }
}
