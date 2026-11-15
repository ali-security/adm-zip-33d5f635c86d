"use strict";

const { expect } = require("chai");
const fs = require("fs");
const os = require("os");
const pth = require("path");
const rimraf = require("rimraf");
const Zip = require("../adm-zip");

// Regression tests for CVE-2026-76845 (GHSA-vwc7-r8mq-g2x9):
// sanitize() only proves the textual entry path stays under the extraction
// root. When a path component that already exists inside the root is a symlink
// pointing elsewhere, extractAllTo / extractAllToAsync / extractEntryTo followed
// it and wrote files (or created directories) outside the root. The archive
// needs no "../" for this, so the string check never fires.

describe("symlink extraction (CVE-2026-76845)", function () {
    let base, root, outside;

    beforeEach(function () {
        base = fs.mkdtempSync(pth.join(os.tmpdir(), "adm-zip-symlink-"));
        root = pth.join(base, "root");
        outside = pth.join(base, "outside");
        fs.mkdirSync(root);
        fs.mkdirSync(outside);
    });

    afterEach(function () {
        // best effort: rimraf removes the links themselves, never their targets
        try {
            rimraf.sync(base);
        } catch (e) {}
    });

    // Create a symlink, skipping the test where the platform refuses to (Windows
    // without the symlink privilege). Directory links are junctions on Windows:
    // they need no privilege, and lstat() reports them as symbolic links too.
    function link(ctx, target, path, isDir) {
        const type = isDir ? (process.platform === "win32" ? "junction" : "dir") : "file";
        try {
            fs.symlinkSync(target, path, type);
        } catch (e) {
            if (e.code === "EPERM" || e.code === "EACCES" || e.code === "ENOSYS") ctx.skip();
            throw e;
        }
    }

    // build an archive from { entryName: content } (null content = directory entry)
    function makeZip(entries) {
        const zip = new Zip();
        Object.keys(entries).forEach(function (name) {
            zip.addFile(name, entries[name] === null ? null : Buffer.from(entries[name]));
        });
        return new Zip(zip.toBuffer());
    }

    function expectRejected(promise, pattern) {
        return promise.then(
            function () {
                throw new Error("extraction through a symlink was expected to fail");
            },
            function (err) {
                expect(err).to.be.an("error");
                expect(err.message).to.match(pattern);
            }
        );
    }

    const IN_THE_WAY = /There is a file in the way/;

    describe("extractAllTo", function () {
        it("does not write a file through a symlinked directory", function () {
            link(this, outside, pth.join(root, "link"), true);
            const zip = makeZip({ "link/victim.txt": "pwned" });

            expect(() => zip.extractAllTo(root, true)).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "victim.txt"))).to.equal(false);
        });

        it("does not write a file through a symlinked directory without overwrite", function () {
            link(this, outside, pth.join(root, "link"), true);
            const zip = makeZip({ "link/victim.txt": "pwned" });

            expect(() => zip.extractAllTo(root, false)).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "victim.txt"))).to.equal(false);
        });

        it("does not overwrite a file outside the root through a symlinked file", function () {
            const victim = pth.join(outside, "victim.txt");
            fs.writeFileSync(victim, "original");
            link(this, victim, pth.join(root, "victim.txt"), false);
            const zip = makeZip({ "victim.txt": "pwned" });

            expect(() => zip.extractAllTo(root, true)).to.throw(IN_THE_WAY);
            expect(fs.readFileSync(victim, "utf8")).to.equal("original");
        });

        it("does not create a directory through a symlinked directory", function () {
            link(this, outside, pth.join(root, "link"), true);
            const zip = makeZip({ "link/sub/": null });

            expect(() => zip.extractAllTo(root, true)).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "sub"))).to.equal(false);
        });

        it("does not write through a symlink nested deeper in the path", function () {
            fs.mkdirSync(pth.join(root, "a"));
            link(this, outside, pth.join(root, "a", "link"), true);
            const zip = makeZip({ "a/link/b/victim.txt": "pwned" });

            expect(() => zip.extractAllTo(root, true)).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "b"))).to.equal(false);
        });
    });

    describe("extractEntryTo", function () {
        it("does not write a file entry through a symlinked directory", function () {
            link(this, outside, pth.join(root, "link"), true);
            const zip = makeZip({ "link/victim.txt": "pwned" });

            expect(() => zip.extractEntryTo("link/victim.txt", root, true, true)).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "victim.txt"))).to.equal(false);
        });

        it("does not overwrite a file outside the root through a symlinked file", function () {
            const victim = pth.join(outside, "victim.txt");
            fs.writeFileSync(victim, "original");
            link(this, victim, pth.join(root, "victim.txt"), false);
            const zip = makeZip({ "dir/victim.txt": "pwned" });

            expect(() => zip.extractEntryTo("dir/victim.txt", root, false, true)).to.throw(IN_THE_WAY);
            expect(fs.readFileSync(victim, "utf8")).to.equal("original");
        });

        it("does not write a directory entry's children through a symlinked directory", function () {
            link(this, outside, pth.join(root, "link"), true);
            const zip = makeZip({ "link/": null, "link/victim.txt": "pwned" });

            expect(() => zip.extractEntryTo("link/", root, true, true)).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "victim.txt"))).to.equal(false);
        });
    });

    describe("extractAllToAsync", function () {
        it("does not write a file through a symlinked directory", function () {
            link(this, outside, pth.join(root, "link"), true);
            const zip = makeZip({ "link/victim.txt": "pwned" });

            return expectRejected(zip.extractAllToAsync(root, true, false), IN_THE_WAY).then(function () {
                expect(fs.existsSync(pth.join(outside, "victim.txt"))).to.equal(false);
            });
        });

        it("does not overwrite a file outside the root through a symlinked file", function () {
            const victim = pth.join(outside, "victim.txt");
            fs.writeFileSync(victim, "original");
            link(this, victim, pth.join(root, "victim.txt"), false);
            const zip = makeZip({ "victim.txt": "pwned" });

            return expectRejected(zip.extractAllToAsync(root, true, false), IN_THE_WAY).then(function () {
                expect(fs.readFileSync(victim, "utf8")).to.equal("original");
            });
        });

        it("does not create a directory through a symlinked directory", function () {
            link(this, outside, pth.join(root, "link"), true);
            const zip = makeZip({ "link/sub/": null });

            return expectRejected(zip.extractAllToAsync(root, true, false), /Unable to create folder/).then(function () {
                expect(fs.existsSync(pth.join(outside, "sub"))).to.equal(false);
            });
        });
    });

    describe("legitimate extraction", function () {
        it("still extracts into a root that is itself reached through a symlink", function () {
            const linkRoot = pth.join(base, "linkroot");
            link(this, root, linkRoot, true);
            const zip = makeZip({ "a/": null, "a/b.txt": "ok", "c.txt": "ok too" });

            zip.extractAllTo(linkRoot, true);
            expect(fs.readFileSync(pth.join(root, "a", "b.txt"), "utf8")).to.equal("ok");
            expect(fs.readFileSync(pth.join(root, "c.txt"), "utf8")).to.equal("ok too");

            expect(zip.extractEntryTo("a/b.txt", linkRoot, false, true)).to.equal(true);
            expect(fs.readFileSync(pth.join(root, "b.txt"), "utf8")).to.equal("ok");
        });

        it("still extracts asynchronously into a root reached through a symlink", function () {
            const linkRoot = pth.join(base, "linkroot");
            link(this, root, linkRoot, true);
            const zip = makeZip({ "a/": null, "a/b.txt": "ok" });

            return zip.extractAllToAsync(linkRoot, true, false).then(function () {
                expect(fs.readFileSync(pth.join(root, "a", "b.txt"), "utf8")).to.equal("ok");
            });
        });

        it("still overwrites regular files and reuses regular directories inside the root", function () {
            fs.mkdirSync(pth.join(root, "a"));
            fs.writeFileSync(pth.join(root, "a", "b.txt"), "old");
            const zip = makeZip({ "a/": null, "a/b.txt": "new" });

            zip.extractAllTo(root, true);
            expect(fs.readFileSync(pth.join(root, "a", "b.txt"), "utf8")).to.equal("new");
        });
    });
});
