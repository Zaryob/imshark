// Regenerate application icons and the embedded welcome logo from resources/logo.png.
// Requires Node.js and sharp (npm install --no-save sharp); macOS also uses iconutil.
const fs = require('node:fs/promises');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const sharp = require('sharp');

async function main() {
    const root = path.resolve(__dirname, '..');
    const resources = path.join(root, 'resources');
    const source = path.join(resources, 'logo.png');
    await sharp(source).resize(1024, 512).png().toFile(path.join(resources, 'welcome-logo.png'));

    // Preserve the supplied artwork, with a light background so the navy lettering remains visible in the Dock.
    const logo = await sharp(source).trim().resize(880, 700, { fit: 'inside' }).png().toBuffer();
    const background = Buffer.from('<svg width="1024" height="1024"><rect x="32" y="32" width="960" height="960" rx="200" fill="#edf7fb"/></svg>');
    const icon = await sharp(background).composite([{ input: logo, gravity: 'centre' }]).png().toBuffer();
    await fs.writeFile(path.join(resources, 'imshark-1024.png'), icon);
    await sharp(icon).resize(256, 256).png().toFile(path.join(resources, 'imshark.png'));

    // PNG-compressed ICO entries cover Explorer, taskbar and title-bar sizes.
    const sizes = [16, 32, 48, 64, 128, 256];
    const images = await Promise.all(sizes.map(size => sharp(icon).resize(size, size).png().toBuffer()));
    const header = Buffer.alloc(6 + sizes.length * 16);
    header.writeUInt16LE(1, 2);
    header.writeUInt16LE(sizes.length, 4);
    let offset = header.length;
    sizes.forEach((size, index) => {
        const entry = 6 + index * 16;
        header[entry] = header[entry + 1] = size === 256 ? 0 : size;
        header.writeUInt16LE(1, entry + 4);
        header.writeUInt16LE(32, entry + 6);
        header.writeUInt32LE(images[index].length, entry + 8);
        header.writeUInt32LE(offset, entry + 12);
        offset += images[index].length;
    });
    await fs.writeFile(path.join(resources, 'imshark.ico'), Buffer.concat([header, ...images]));

    if (process.platform === 'darwin') {
        const iconset = await fs.mkdtemp(path.join(require('node:os').tmpdir(), 'imshark-'));
        const directory = path.join(iconset, 'imshark.iconset');
        await fs.mkdir(directory);
        try {
            for (const size of [16, 32, 128, 256, 512]) {
                for (const scale of [1, 2]) {
                    const suffix = scale === 2 ? '@2x' : '';
                    await sharp(icon).resize(size * scale, size * scale).png()
                        .toFile(path.join(directory, `icon_${size}x${size}${suffix}.png`));
                }
            }
            execFileSync('iconutil', ['-c', 'icns', directory, '-o', path.join(resources, 'imshark.icns')]);
        } finally {
            await fs.rm(iconset, { recursive: true, force: true });
        }
    }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
