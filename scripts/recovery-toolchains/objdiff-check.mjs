#!/usr/bin/env node
/**
 * objdiff-check.mjs -- verify COFF objects with objdiff-wasm.
 *
 * Set AGENT_DECOMPILE_OBJDIFF_WASM_ROOT or MIZUCHI_ROOT to a tree that contains
 * node_modules/objdiff-wasm/dist/objdiff.js
 */
import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';

const WASM_ROOT =
  process.env.AGENT_DECOMPILE_OBJDIFF_WASM_ROOT ||
  process.env.MIZUCHI_ROOT ||
  '';
const OBJDIFF_ENTRY = WASM_ROOT
  ? path.join(WASM_ROOT, 'node_modules/objdiff-wasm/dist/objdiff.js')
  : '';

async function loadObjdiff() {
  if (!OBJDIFF_ENTRY) {
    throw new Error('set AGENT_DECOMPILE_OBJDIFF_WASM_ROOT or MIZUCHI_ROOT');
  }
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input) => {
    const url = input.toString();
    if (url.includes('objdiff.core.wasm')) {
      const buffer = await fs.readFile(fileURLToPath(url));
      return new Response(buffer, { headers: { 'content-type': 'application/wasm' } });
    }
    return originalFetch(input);
  };
  try {
    const objdiff = await import(pathToFileURL(OBJDIFF_ENTRY).href);
    objdiff.init('error');
    return objdiff;
  } finally {
    globalThis.fetch = originalFetch;
  }
}

function rowToText(objdiff, row) {
  let text = '';
  for (const segment of row.segments) {
    const t = segment.text;
    switch (t.tag) {
      case 'basic':
      case 'opaque':
        text += t.val;
        break;
      case 'opcode':
        text += `${t.val.mnemonic} `;
        break;
      case 'signed':
      case 'unsigned':
      case 'addend':
        text += `0x${Number(t.val).toString(16)}`;
        break;
      case 'branch-dest':
        text += `.L${Number(t.val).toString(16)}`;
        break;
      case 'symbol':
        text += t.val.demangledName || t.val.name;
        break;
      case 'spacing':
        text += ' '.repeat(t.val);
        break;
      default:
        break;
    }
  }
  return text.replace(/\s+/g, ' ').trim();
}

async function main() {
  const args = process.argv.slice(2);
  const objdiff = await loadObjdiff();
  console.log(`objdiff-wasm version: ${objdiff.version()}`);
  const config = new objdiff.diff.DiffConfig();

  const parse = async (file, side) => {
    const bytes = new Uint8Array(await fs.readFile(file));
    return objdiff.diff.Object.parse(bytes, config, side);
  };

  if (args[0] === '--symbols') {
    const obj = await parse(args[1], 'base');
    const { left } = objdiff.diff.runDiff(obj, undefined, config, {
      mappings: [],
      selectingLeft: undefined,
      selectingRight: undefined,
    });
    const sections = objdiff.display.displaySections(
      left,
      {},
      { showHiddenSymbols: true, showMappedSymbols: false, reverseFnOrder: false },
    );
    for (const section of sections) {
      console.log(`section ${section.name} (${section.size} bytes)`);
      for (const ref of section.symbols) {
        const sym = objdiff.display.displaySymbol(left, ref);
        console.log(`  ${sym.info.name}  kind=${sym.info.kind} size=${sym.info.size} rows=${sym.rowCount}`);
      }
    }
    return;
  }

  const [baseFile, targetFile, symbolArg] = args;
  if (!baseFile || !targetFile) {
    console.error('usage: objdiff-check.mjs <base.o> <target.o> [symbol]');
    process.exit(2);
  }

  const [baseObj, targetObj] = await Promise.all([parse(baseFile, 'base'), parse(targetFile, 'target')]);
  const { left, right } = objdiff.diff.runDiff(baseObj, targetObj, config, {
    mappings: [],
    selectingLeft: undefined,
    selectingRight: undefined,
  });
  if (!left) throw new Error(`objdiff failed to parse base object ${baseFile}`);
  if (!right) throw new Error(`objdiff failed to parse target object ${targetFile}`);

  let symbolName = symbolArg;
  if (!symbolName) {
    const sections = objdiff.display.displaySections(
      left,
      {},
      { showHiddenSymbols: false, showMappedSymbols: false, reverseFnOrder: false },
    );
    for (const section of sections) {
      for (const ref of section.symbols) {
        const sym = objdiff.display.displaySymbol(left, ref);
        if (sym.info.kind === 'function') {
          symbolName = sym.info.name;
          break;
        }
      }
      if (symbolName) break;
    }
  }
  if (!symbolName) throw new Error('no function symbol found in the base object');

  const leftSym = left.findSymbol(symbolName, undefined);
  const rightSym = right.findSymbol(symbolName, undefined);
  if (!leftSym) throw new Error(`symbol "${symbolName}" not found in ${baseFile}`);
  if (!rightSym) throw new Error(`symbol "${symbolName}" not found in ${targetFile}`);

  const leftDisplay = objdiff.display.displaySymbol(left, leftSym.id);
  const rightDisplay = objdiff.display.displaySymbol(right, rightSym.id);
  const rows = Math.max(leftDisplay.rowCount, rightDisplay.rowCount);

  let same = 0;
  let differing = 0;
  const details = [];
  for (let i = 0; i < rows; i++) {
    let l = '';
    let r = '';
    let lk = 'none';
    let rk = 'none';
    try {
      const row = objdiff.display.displayInstructionRow(left, leftSym.id, i, config);
      l = rowToText(objdiff, row);
      lk = row.diffKind;
    } catch {}
    try {
      const row = objdiff.display.displayInstructionRow(right, rightSym.id, i, config);
      r = rowToText(objdiff, row);
      rk = row.diffKind;
    } catch {}
    if (l === r && lk === 'none' && rk === 'none') same++;
    else {
      differing++;
      details.push(`  row ${i}: base=${JSON.stringify(l)} [${lk}]  target=${JSON.stringify(r)} [${rk}]`);
    }
  }

  console.log(`symbol: ${symbolName}`);
  console.log(`base   : ${baseFile} (${leftDisplay.rowCount} rows, matchPercent=${leftDisplay.matchPercent})`);
  console.log(`target : ${targetFile} (${rightDisplay.rowCount} rows, matchPercent=${rightDisplay.matchPercent})`);
  console.log(`rows identical: ${same}, differing: ${differing}`);
  if (details.length) console.log(details.join('\n'));
  const percent = leftDisplay.matchPercent ?? (differing === 0 ? 100 : 0);
  console.log(`RESULT: ${differing === 0 && percent === 100 ? 'MATCH 100%' : `MISMATCH (${percent}%)`}`);
  process.exit(differing === 0 && percent === 100 ? 0 : 1);
}

main().catch((error) => {
  console.error(error);
  process.exit(3);
});
