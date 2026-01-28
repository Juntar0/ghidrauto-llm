// PeekMemory.java
//
// Usage (via analyzeHeadless):
//   -postScript PeekMemory.java <output_json_path> <va_hex> <len>
//
// Writes a JSON file containing base64 bytes plus basic annotations.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class PeekMemory extends GhidraScript {

  private static String jsonEscape(String s) {
    if (s == null) return "";
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch (c) {
        case '"': sb.append("\\\""); break;
        case '\\': sb.append("\\\\"); break;
        case '\n': sb.append("\\n"); break;
        case '\r': sb.append("\\r"); break;
        case '\t': sb.append("\\t"); break;
        default:
          if (c < 0x20) {
            sb.append(String.format("\\u%04x", (int)c));
          } else {
            sb.append(c);
          }
      }
    }
    return sb.toString();
  }

  private static long parseHex(String s) {
    String x = s.trim();
    if (x.startsWith("0x") || x.startsWith("0X")) x = x.substring(2);
    // allow underscores
    x = x.replace("_", "");
    return Long.parseUnsignedLong(x, 16);
  }

  @Override
  public void run() throws Exception {
    if (currentProgram == null) {
      throw new RuntimeException("No currentProgram");
    }

    if (getScriptArgs().length < 3) {
      throw new RuntimeException("Usage: PeekMemory.java <output_json_path> <va_hex> <len>");
    }

    String outPath = getScriptArgs()[0];
    String vaStr = getScriptArgs()[1];
    String lenStr = getScriptArgs()[2];

    long va = parseHex(vaStr);
    int len = Integer.parseInt(lenStr);
    if (len <= 0) len = 1;
    if (len > 0x4000) len = 0x4000; // hard safety

    Program p = currentProgram;
    Memory mem = p.getMemory();
    Address addr = p.getAddressFactory().getDefaultAddressSpace().getAddress(va);

    byte[] buf = new byte[len];
    int read = 0;
    String error = null;

    try {
      read = mem.getBytes(addr, buf);
    } catch (Exception e) {
      error = e.toString();
      // still write json
    }

    if (read < len && read > 0) {
      byte[] shrunk = new byte[read];
      System.arraycopy(buf, 0, shrunk, 0, read);
      buf = shrunk;
      len = read;
    }

    MemoryBlock blk = null;
    String section = null;
    String perm = null;
    try {
      blk = mem.getBlock(addr);
      if (blk != null) {
        section = blk.getName();
        StringBuilder psb = new StringBuilder();
        psb.append(blk.isRead() ? 'r' : '-');
        psb.append(blk.isWrite() ? 'w' : '-');
        psb.append(blk.isExecute() ? 'x' : '-');
        perm = psb.toString();
      }
    } catch (Exception e) {
      // ignore
    }

    String label = null;
    try {
      SymbolTable st = p.getSymbolTable();
      Symbol sym = st.getPrimarySymbol(addr);
      if (sym != null) {
        label = sym.getName();
      }
    } catch (Exception e) {
      // ignore
    }

    long imageBase = 0;
    long imageSize = 0;
    try {
      imageBase = p.getImageBase().getOffset();
      Address min = mem.getMinAddress();
      Address max = mem.getMaxAddress();
      if (min != null && max != null) {
        // approximate size as max-min+1
        imageSize = (max.getOffset() - min.getOffset()) + 1;
      }
    } catch (Exception e) {
      // ignore
    }

    int ptrSize = 0;
    try {
      ptrSize = p.getDefaultPointerSize();
    } catch (Exception e) {
      ptrSize = 0;
    }

    String arch = null;
    try {
      // Best-effort string; UI only needs x86/x64 distinction.
      String lang = p.getLanguageID().toString().toLowerCase();
      if (lang.contains("x86")) {
        arch = (ptrSize == 8) ? "x64" : "x86";
      }
    } catch (Exception e) {
      // ignore
    }

    String b64 = Base64.getEncoder().encodeToString(buf);

    StringBuilder js = new StringBuilder();
    js.append("{");
    if (error != null) {
      js.append("\"error\":\"").append(jsonEscape(error)).append("\",");
    }
    js.append("\"va\":\"0x").append(Long.toHexString(va)).append("\",");
    js.append("\"len\":").append(len).append(",");
    js.append("\"bytes_b64\":\"").append(b64).append("\",");
    js.append("\"arch\":").append(arch == null ? "null" : ("\"" + jsonEscape(arch) + "\"")).append(",");
    js.append("\"ptr_size\":").append(ptrSize).append(",");
    js.append("\"annotations\":{");
    js.append("\"image_base\":\"0x").append(Long.toHexString(imageBase)).append("\"");
    js.append(",\"image_size\":").append(imageSize);
    if (section != null) js.append(",\"section\":\"").append(jsonEscape(section)).append("\"");
    if (perm != null) js.append(",\"perm\":\"").append(jsonEscape(perm)).append("\"");
    if (label != null) js.append(",\"label\":\"").append(jsonEscape(label)).append("\"");
    js.append("}}\n");

    File out = new File(outPath);
    out.getParentFile().mkdirs();
    try (FileOutputStream fos = new FileOutputStream(out)) {
      fos.write(js.toString().getBytes(StandardCharsets.UTF_8));
    }

    Msg.info(this, "PeekMemory wrote: " + out.getAbsolutePath());
  }
}
