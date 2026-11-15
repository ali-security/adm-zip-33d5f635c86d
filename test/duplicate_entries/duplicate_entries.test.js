"use strict";

// GHSA-p634-w6r4-rjp2: a ZIP can declare two entries with the same name.
// adm-zip kept both in its entry list but only the last one in its name table,
// so getEntry() (table) and extractAllTo() (list) resolved the same name to
// different content: an application validating an entry via getEntry() before
// extracting could approve one file while a different one landed on disk.
// Archives with duplicate entry names are now rejected when they are read.

const assert = require("assert");
const fs = require("fs");
const pth = require("path");
const Zip = require("../../adm-zip");
const rimraf = require("rimraf");

const DUPLICATE = /Duplicate entry name/;

// Builds the advisory's PoC: "a.txt" (FIRST) and "b.txt" (SECOND), then
// byte-patches the "a.txt" name to "b.txt" in both the local and the central
// directory headers so the archive declares "b.txt" twice.
function craftDuplicateArchive() {
    const zip = new Zip({ noSort: true });
    zip.addFile("a.txt", Buffer.from("FIRST"));
    zip.addFile("b.txt", Buffer.from("SECOND"));
    const buf = zip.toBuffer();

    const from = Buffer.from("a.txt");
    const to = Buffer.from("b.txt");
    let patched = 0;
    let pos = buf.indexOf(from);
    while (pos !== -1) {
        to.copy(buf, pos);
        patched++;
        pos = buf.indexOf(from, pos + to.length);
    }
    // one local file header + one central directory header
    assert.strictEqual(patched, 2);
    return buf;
}

describe("ADM-ZIP - duplicate entry names (GHSA-p634-w6r4-rjp2)", () => {
    const destination = pth.resolve("./test/xxx");
    const unzipped = pth.join(destination, "unzipped");

    afterEach((done) => rimraf(destination, done));

    it("rejects the archive on getEntry()/readFile()", () => {
        const buf = craftDuplicateArchive();
        assert.throws(() => new Zip(buf).getEntry("b.txt"), DUPLICATE);
        assert.throws(() => new Zip(buf).readFile("b.txt"), DUPLICATE);
    });

    it("rejects the archive on getEntries()/forEach() listing", () => {
        const buf = craftDuplicateArchive();
        assert.throws(() => new Zip(buf).getEntries(), DUPLICATE);
        assert.throws(() => new Zip(buf).forEach(() => {}), DUPLICATE);
    });

    it("rejects the archive at construction when entries are read eagerly", () => {
        const buf = craftDuplicateArchive();
        assert.throws(() => new Zip(buf, { readEntries: true }), DUPLICATE);
    });

    it("extractAllTo() fails closed and writes nothing", () => {
        const buf = craftDuplicateArchive();
        const zip = new Zip(buf);
        assert.throws(() => zip.extractAllTo(unzipped, false), DUPLICATE);
        assert.strictEqual(fs.existsSync(pth.join(unzipped, "b.txt")), false);
    });

    it("extractAllToAsync() rejects and writes nothing", async () => {
        const buf = craftDuplicateArchive();
        const zip = new Zip(buf);
        await assert.rejects(zip.extractAllToAsync(unzipped, false, false), DUPLICATE);
        assert.strictEqual(fs.existsSync(pth.join(unzipped, "b.txt")), false);
    });

    it("validate-then-extract cannot be split between two duplicate entries", () => {
        const zip = new Zip(craftDuplicateArchive());
        assert.throws(() => {
            // advisory PoC: getEntry() returned "SECOND" while extractAllTo() wrote "FIRST"
            const validated = zip.getEntry("b.txt").getData().toString();
            zip.extractAllTo(unzipped, false);
            assert.strictEqual(fs.readFileSync(pth.join(unzipped, "b.txt"), "utf8"), validated);
        }, DUPLICATE);
    });

    it("still reads archives whose entry names are distinct, including Object.prototype keys", () => {
        const zip = new Zip();
        zip.addFile("b.txt", Buffer.from("one"));
        zip.addFile("B.txt", Buffer.from("two"));
        zip.addFile("dir/b.txt", Buffer.from("three"));
        zip.addFile("constructor", Buffer.from("four"));
        zip.addFile("toString", Buffer.from("five"));
        zip.addFile("hasOwnProperty", Buffer.from("six"));
        // adding the same name again updates the existing entry, it does not duplicate it
        zip.addFile("b.txt", Buffer.from("one-updated"));

        const reopened = new Zip(zip.toBuffer());
        assert.deepStrictEqual(
            reopened
                .getEntries()
                .map((e) => e.entryName)
                .sort(),
            ["B.txt", "b.txt", "constructor", "dir/b.txt", "hasOwnProperty", "toString"]
        );
        assert.strictEqual(reopened.readFile("b.txt").toString(), "one-updated");
        assert.strictEqual(reopened.readFile("B.txt").toString(), "two");
        assert.strictEqual(reopened.readFile("dir/b.txt").toString(), "three");
        assert.strictEqual(reopened.readFile("constructor").toString(), "four");
        assert.strictEqual(reopened.readFile("toString").toString(), "five");
        assert.strictEqual(reopened.readFile("hasOwnProperty").toString(), "six");
    });
});
