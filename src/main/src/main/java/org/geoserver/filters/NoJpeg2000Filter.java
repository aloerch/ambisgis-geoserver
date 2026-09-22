/* Authored for the AmbisGIS NO-JPEG2000 Java/server candidate, 2026.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.geoserver.filters;

import java.io.IOException;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.io.PushbackInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipException;
import java.util.Enumeration;
import java.util.Locale;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ReadListener;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

/** Runs after the existing security chain; rejects an explicit unsupported capability. */
public final class NoJpeg2000Filter implements Filter {
    @Override public void init(FilterConfig config) { }
    @Override public void destroy() { }
    private static void reject(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE);
        response.setContentType("text/plain;charset=UTF-8");
        response.setHeader("Cache-Control", "no-store");
        response.getWriter().write(NoJpeg2000Policy.MESSAGE);
    }

    @Override
    public void doFilter(ServletRequest incoming, ServletResponse outgoing, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) incoming;
        HttpServletResponse response = (HttpServletResponse) outgoing;
        String path = request.getRequestURI().substring(request.getContextPath().length());
        // Only selected protocol format parameters are capability selections. Layer names,
        // catalog titles and ordinary JSON properties are never interpreted as codecs.
        String operation = null;
        Enumeration<String> parameterNames = request.getParameterNames();
        while (parameterNames.hasMoreElements()) {
            String name = parameterNames.nextElement();
            if (name.equalsIgnoreCase("request")) operation = request.getParameter(name);
        }
        boolean output = operation != null && (operation.equalsIgnoreCase("GetMap")
                || operation.equalsIgnoreCase("GetCoverage") || operation.equalsIgnoreCase("GetTile"));
        if (output) {
            Enumeration<String> names = request.getParameterNames();
            while (names.hasMoreElements()) {
                String name = names.nextElement();
                if (name.equalsIgnoreCase("format") || name.equalsIgnoreCase("outputformat")) {
                    for (String value : request.getParameterValues(name)) {
                        if (NoJpeg2000Policy.format(value)) { reject(response); return; }
                    }
                }
            }
        }
        boolean upload = (path.matches("/rest/workspaces/[^/]+/coveragestores/[^/]+/(file|url|external|remote)[.][^/]+")
                || path.matches("/rest/imports/[0-9]+/tasks/[^/]+"))
                && (request.getMethod().equals("PUT") || request.getMethod().equals("POST"));
        String type = request.getContentType();
        String media = type == null ? "" : type.toLowerCase(Locale.ROOT);
        if (upload && (NoJpeg2000Policy.filename(path)
                || NoJpeg2000Policy.filename(request.getParameter("filename")) || NoJpeg2000Policy.format(type))) {
            reject(response); return;
        }
        boolean binaryRoute = path.matches("/rest/workspaces/[^/]+/coveragestores/[^/]+/file[.][^/]+")
                || path.matches("/rest/imports/[0-9]+/tasks/[^/]+[.][^/]+");
        // File upload routes are binary even if a client supplies a misleading MIME type.
        // Native JSON/XML metadata bodies preserve their parser and encoding semantics.
        // Multipart parts and extracted coverage ZIP members have separate pre-write checks.
        if (upload && (binaryRoute || !media.contains("json") && !media.contains("xml")
                && !media.startsWith("multipart/") && !media.startsWith("application/x-www-form-urlencoded"))) {
            ServletInputStream original = request.getInputStream();
            PushbackInputStream input = new PushbackInputStream(original, 12);
            byte[] prefix = input.readNBytes(12);
            if (NoJpeg2000Policy.signature(prefix)) { reject(response); return; }
            input.unread(prefix);
            Path archive = null;
            try {
                if (NoJpeg2000Policy.zipSignature(prefix)) {
                    if (request.getContentLengthLong() > NoJpeg2000Policy.MAX_ARCHIVE_BYTES)
                        throw new NoJpeg2000Policy.InputLimit();
                    archive = Files.createTempFile("AmbisgisCodecRequest", ".zip");
                    NoJpeg2000Policy.stageArchive(input, archive);
                    if (NoJpeg2000Policy.archive(archive)) {
                        Files.deleteIfExists(archive); reject(response); return;
                    }
                    input = new PushbackInputStream(Files.newInputStream(archive), 12);
                }
            } catch (NoJpeg2000Policy.InputLimit limit) {
                if (archive != null) Files.deleteIfExists(archive);
                response.setStatus(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
                response.setContentType("text/plain;charset=UTF-8");
                response.getWriter().write(NoJpeg2000Policy.LIMIT_MESSAGE);
                return;
            } catch (ZipException malformed) {
                if (archive != null) Files.deleteIfExists(archive);
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                response.setContentType("text/plain;charset=UTF-8");
                response.getWriter().write("Invalid ZIP upload.");
                return;
            } catch (IOException | RuntimeException error) {
                if (archive != null) Files.deleteIfExists(archive);
                throw error;
            }
            final PushbackInputStream replayInput = input;
            final Path stagedArchive = archive;
            ServletInputStream replay = new ServletInputStream() {
                @Override public int read() throws IOException { return replayInput.read(); }
                @Override public int read(byte[] b, int off, int len) throws IOException { return replayInput.read(b, off, len); }
                @Override public void close() throws IOException { replayInput.close(); }
                @Override public boolean isFinished() { return original.isFinished() && availablePrefix() == 0; }
                private int availablePrefix() { try { return replayInput.available(); } catch (IOException e) { return 0; } }
                @Override public boolean isReady() { return original.isReady() || availablePrefix() > 0; }
                @Override public void setReadListener(ReadListener listener) { original.setReadListener(listener); }
            };
            try {
                chain.doFilter(new HttpServletRequestWrapper(request) {
                @Override public ServletInputStream getInputStream() { return replay; }
                @Override public BufferedReader getReader() throws IOException {
                    String encoding = getCharacterEncoding();
                    return new BufferedReader(new InputStreamReader(replay,
                            encoding == null ? StandardCharsets.ISO_8859_1.name() : encoding));
                }
                }, response);
            } finally {
                if (stagedArchive != null) { replayInput.close(); Files.deleteIfExists(stagedArchive); }
            }
            return;
        }
        chain.doFilter(request, response);
    }
}
