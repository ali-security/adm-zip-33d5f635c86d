"use strict";

const { expect } = require("chai");
const zlib = require("zlib");
const Zip = require("../adm-zip");
const { crc32 } = require("../util/utils");

// Regression test for CVE-2026-39244:
// adm-zip allocated the entry output buffer from the attacker-declared
// uncompressed size (central-directory / local-header size field) before any
// validation. A tiny crafted archive could declare a ~4 GB size and force a
// matching Buffer.alloc, OOM-killing the process. The allocation must be bound
// by the data actually present in the archive, not by the declared size.

const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n >>> 0);
    return b;
};
const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
};

// Build a single-entry zip that declares `declaredSize` uncompressed bytes while
// only carrying `content` bytes of payload. The crc defaults to 0, which is
// deliberately wrong: alloc used to happen before the crc check.
function craftBomb(declaredSize, method, content, crc = 0) {
    const name = Buffer.from("a");
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        name,
        content
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

describe("decompression bomb (declared size) - CVE-2026-39244", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB, far above any plausible RSS budget

    it("does not allocate the declared size for a STORED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const before = process.memoryUsage().rss;
        // invalid crc -> must throw, but crucially without committing gigabytes
        expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size for a DEFLATED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
        const before = process.memoryUsage().rss;
        // bogus deflate stream / crc -> must throw without a huge eager allocation
        expect(() => zip.getEntries()[0].getData()).to.throw();
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("still reads a legitimate STORED entry", () => {
        const zip = new Zip();
        zip.addFile("s.bin", Buffer.from([1, 2, 3, 4, 5]));
        const round = new Zip(zip.toBuffer());
        expect([...round.readFile("s.bin")]).to.eql([1, 2, 3, 4, 5]);
    });

    it("still reads a legitimate DEFLATED entry", () => {
        const zip = new Zip();
        const payload = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        expect(round.readFile("d.txt").equals(payload)).to.equal(true);
    });
});

// Regression test for GHSA-c6fg-446q-cg94:
// the synchronous getData() path caps inflation at the declared uncompressed
// size (zlib maxOutputLength), but getDataAsync() used the zlib streaming API,
// which ignores maxOutputLength, so a small archive could inflate without limit
// through the async path. The async path must enforce the same cap.
describe("decompression bomb (async size cap) - GHSA-c6fg-446q-cg94", () => {
    // A real deflate stream whose inflated size (1 MiB, many zlib chunks) dwarfs
    // the size the archive declares. The crc is correct for the real data, so
    // only the size cap stands between the caller and the oversized buffer.
    const real = Buffer.alloc(1024 * 1024, 0x41);
    const deflated = zlib.deflateRawSync(real);
    const realCrc = crc32(real);

    const expectCapped = (declared, done) => (data, err) => {
        try {
            expect(err, "inflating past the declared size must fail").to.be.an("error");
            expect(err.message).to.contain("exceeds the declared uncompressed size");
            expect(data.length, "no oversized buffer may be returned").to.be.at.most(declared);
            done();
        } catch (e) {
            done(e);
        }
    };

    it("getDataAsync stops at the declared uncompressed size", (done) => {
        const DECLARED = 100;
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, deflated, realCrc));
        zip.getEntries()[0].getDataAsync(expectCapped(DECLARED, done));
    });

    it("getDataAsync does not treat a declared size of 0 as unlimited", (done) => {
        const zip = new Zip(craftBomb(0, 8 /* DEFLATED */, deflated, realCrc));
        zip.getEntries()[0].getDataAsync(expectCapped(0, done));
    });

    it("readFileAsync stops at the declared uncompressed size", (done) => {
        const DECLARED = 100;
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, deflated, realCrc));
        zip.readFileAsync(zip.getEntries()[0], expectCapped(DECLARED, done));
    });

    it("getDataAsync still reads a legitimate DEFLATED entry", (done) => {
        const zip = new Zip();
        const payload = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        round.readFileAsync("d.txt", (data, err) => {
            try {
                expect(err).to.equal(undefined);
                expect(data.equals(payload)).to.equal(true);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("still reads a genuinely empty DEFLATED entry declaring size 0", (done) => {
        const empty = Buffer.alloc(0);
        const zip = new Zip(craftBomb(0, 8 /* DEFLATED */, zlib.deflateRawSync(empty), crc32(empty)));
        const entry = zip.getEntries()[0];
        expect(entry.getData().length).to.equal(0);
        entry.getDataAsync((data, err) => {
            try {
                expect(err).to.equal(undefined);
                expect(data.length).to.equal(0);
                done();
            } catch (e) {
                done(e);
            }
        });
    });
});
