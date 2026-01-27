// ExtractAnalysis.java
//@author clawd
//@category AutoRE

import java.io.*;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.*;

public class ExtractAnalysis extends GhidraScript {

	// Import information holder
	private static class ImportInfo {
		String dll;
		String address;
		boolean isWinApi;
	}

	// Function metadata holder (for JSON generation)
	private static class FunctionMeta {
		String id;
		String name;
		String entry;
		long size;
		boolean isExternal;
		boolean isWinApi;
		boolean isThunk;
		String dll;
		LinkedHashSet<String> callsOut;
		LinkedHashSet<String> calledBy;
	}

	private static boolean isWindowsDLL(String lib) {
		if (lib == null) return false;
		String lower = lib.toLowerCase();
		
		// Core Windows system DLLs
		if (lower.startsWith("kernel32")) return true;
		if (lower.startsWith("user32")) return true;
		if (lower.startsWith("advapi32")) return true;
		if (lower.startsWith("ntdll")) return true;
		if (lower.startsWith("msvcrt")) return true;
		if (lower.startsWith("gdi32")) return true;
		if (lower.startsWith("ws2_32")) return true;
		if (lower.startsWith("shell32")) return true;
		if (lower.startsWith("ole32")) return true;
		if (lower.startsWith("comctl32")) return true;
		if (lower.startsWith("comdlg32")) return true;
		if (lower.startsWith("shlwapi")) return true;
		if (lower.startsWith("wininet")) return true;
		if (lower.startsWith("crypt32")) return true;
		if (lower.startsWith("bcrypt")) return true;
		if (lower.startsWith("secur32")) return true;
		if (lower.startsWith("winmm")) return true;
		if (lower.startsWith("version")) return true;
		if (lower.startsWith("iphlpapi")) return true;
		if (lower.startsWith("winsock")) return true;
		
		// API-MS-WIN-* (Windows 10+ API sets)
		if (lower.startsWith("api-ms-win-")) return true;
		if (lower.startsWith("ext-ms-")) return true;
		
		// Other common Windows DLLs
		if (lower.contains("ucrt")) return true;
		if (lower.contains("vcruntime")) return true;
		
		return false;
	}

	private static boolean looksLikeString(String s) {
		if (s == null) return false;
		String t = s.trim();
		if (t.length() < 2) return false;
		// skip huge blobs
		if (t.length() > 4096) return false;
		int printable = 0;
		for (int i = 0; i < t.length(); i++) {
			char c = t.charAt(i);
			if (c == '\n' || c == '\r' || c == '\t') { printable++; continue; }
			if (c >= 0x20 && c <= 0x7e) printable++;
		}
		return printable >= (int)(t.length() * 0.7);
	}

	private static long lastStatusWriteMs = 0;

	private static String addrStr(Address a) {
		if (a == null) return null;
		return a.toString();
	}

	private static String sanitize(String s) {
		return s.replaceAll("[^A-Za-z0-9_\\-\\.]", "_");
	}

	private static String jsonEsc(String s) {
		if (s == null) return null;
		return s
			.replace("\\", "\\\\")
			.replace("\"", "\\\"")
			.replace("\n", "\\n")
			.replace("\r", "\\r")
			.replace("\t", "\\t");
	}

	private static void writeStatus(File statusPath, String stage, int total, int done, String current) {
		if (statusPath == null) return;
		try {
			statusPath.getParentFile().mkdirs();
			StringBuilder sb = new StringBuilder();
			sb.append("{\n");
			sb.append("  \"stage\":\"").append(jsonEsc(stage)).append("\",\n");
			sb.append("  \"total\":").append(total).append(",\n");
			sb.append("  \"done\":").append(done).append(",\n");
			if (current == null) sb.append("  \"current\":null\n");
			else sb.append("  \"current\":\"").append(jsonEsc(current)).append("\"\n");
			sb.append("}\n");
			try (Writer w = new OutputStreamWriter(new FileOutputStream(statusPath), "UTF-8")) {
				w.write(sb.toString());
			}
		} catch (Exception e) {
			// ignore
		}
	}

	private void writeDisasm(Function f, File outDir) throws IOException {
		Listing listing = currentProgram.getListing();
		InstructionIterator it = listing.getInstructions(f.getBody(), true);
		List<String> lines = new ArrayList<>();
		int limit = 400;
		int i = 0;
		while (it.hasNext() && i < limit) {
			Instruction ins = it.next();
			lines.add(ins.getAddress().toString() + " " + ins.toString());
			i++;
		}
		String fid = sanitize(f.getName());
		File out = new File(outDir, fid + ".txt");
		try (Writer w = new OutputStreamWriter(new FileOutputStream(out), "UTF-8")) {
			for (int j = 0; j < lines.size(); j++) {
				w.write(lines.get(j));
				w.write("\n");
			}
		}
	}

	private DecompileResults decompileOnce(DecompInterface ifc, Function f) {
		try {
			return ifc.decompileFunction(f, 30, monitor);
		} catch (Exception e) {
			return null;
		}
	}

	private void writeDecompAndPcode(DecompInterface ifc, Function f, File decompDir, File pcodeDir) throws IOException {
		String fid = sanitize(f.getName());

		DecompileResults res = decompileOnce(ifc, f);

		// --- C-like decompile
		File outC = new File(decompDir, fid + ".c");
		String cText = "";
		try {
			if (res != null && res.decompileCompleted()) {
				DecompiledFunction df = res.getDecompiledFunction();
				if (df != null) cText = df.getC();
			} else if (res != null) {
				cText = "// decompile_failed: " + res.getErrorMessage();
			} else {
				cText = "// decompile_failed: null results";
			}
		} catch (Exception e) {
			cText = "// decompile_exception: " + e.toString();
		}
		if (cText == null) cText = "";
		int cLines = 0;
		try {
			for (String _l : cText.split("\\r?\\n")) { cLines++; }
		} catch (Exception e) {
			cLines = 0;
		}
		try (Writer w = new OutputStreamWriter(new FileOutputStream(outC), "UTF-8")) {
			w.write("// lines=" + cLines + "\n");
			w.write(cText);
			if (!cText.endsWith("\n")) w.write("\n");
		}

		// --- P-code
		File outP = new File(pcodeDir, fid + ".txt");
		StringBuilder p = new StringBuilder();
		int pOps = 0;
		try {
			if (res != null && res.decompileCompleted()) {
				HighFunction hf = res.getHighFunction();
				if (hf != null) {
					Iterator<PcodeOpAST> it = hf.getPcodeOps();
					int limit = 20000;
					int i = 0;
					p.append("// pcode for ").append(f.getName()).append("\n");
					while (it.hasNext() && i < limit) {
						PcodeOpAST op = it.next();
						SequenceNumber sn = op.getSeqnum();
						String addr = (sn != null && sn.getTarget() != null) ? sn.getTarget().toString() : "";
						p.append(addr);
						p.append(" ");
						p.append(op.getMnemonic());
						p.append(" ");
						p.append(op.toString());
						p.append("\n");
						i++;
					}
					pOps = i;
					if (i == 0) {
						p.append("// pcode_empty\n");
					}
				} else {
					p.append("// pcode_unavailable: no HighFunction\n");
				}
			} else if (res != null) {
				p.append("// pcode_unavailable: ").append(res.getErrorMessage()).append("\n");
			} else {
				p.append("// pcode_unavailable: null results\n");
			}
		} catch (Exception e) {
			p.append("// pcode_exception: ").append(e.toString()).append("\n");
		}
		try (Writer w = new OutputStreamWriter(new FileOutputStream(outP), "UTF-8")) {
			w.write("// lines=" + (p.toString().split("\\r?\\n").length) + " ops=" + pOps + "\n");
			w.write(p.toString());
		}
	}

	private Map<String, ImportInfo> extractImports() {
		Map<String, ImportInfo> importMap = new HashMap<>();
		try {
			ExternalManager em = currentProgram.getExternalManager();
			String[] libNames = em.getExternalLibraryNames();
			
			for (String lib : libNames) {
				if (lib == null || lib.trim().isEmpty()) continue;
				boolean isWinApi = isWindowsDLL(lib);
				
				try {
					Iterator<ExternalLocation> it = em.getExternalLocations(lib);
					while (it != null && it.hasNext()) {
						ExternalLocation loc = it.next();
						String apiName = loc.getLabel();
						if (apiName == null || apiName.trim().isEmpty()) continue;
						
						Address addr = loc.getAddress();
						
						ImportInfo info = new ImportInfo();
						info.dll = lib;
						info.address = addr != null ? addr.toString() : null;
						info.isWinApi = isWinApi;
						
						importMap.put(apiName, info);
					}
				} catch (Exception e) {
					// Skip this library if error
				}
			}
		} catch (Exception e) {
			// Return empty map if error
		}
		return importMap;
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 5) {
			println("ExtractAnalysis requires args: <analysis.json> <disasm_dir> <decomp_dir> <pcode_dir> <status.json>");
			return;
		}

		File analysisPath = new File(args[0]);
		File disasmDir = new File(args[1]);
		File decompDir = new File(args[2]);
		File pcodeDir = new File(args[3]);
		File statusPath = new File(args[4]);
		if (!disasmDir.exists()) disasmDir.mkdirs();
		if (!decompDir.exists()) decompDir.mkdirs();
		if (!pcodeDir.exists()) pcodeDir.mkdirs();

		FunctionManager fm = currentProgram.getFunctionManager();

		DecompInterface ifc = new DecompInterface();
		ifc.setOptions(new DecompileOptions());
		ifc.toggleCCode(true);
		ifc.toggleSyntaxTree(false);
		ifc.setSimplificationStyle("decompile");
		ifc.openProgram(currentProgram);

		List<Function> funcs = new ArrayList<>();
		FunctionIterator fit = fm.getFunctions(true);
		while (fit.hasNext()) {
			funcs.add(fit.next());
		}
		funcs.sort(Comparator.comparingLong(f -> f.getEntryPoint().getOffset()));

		// Extract import table
		Map<String, ImportInfo> importMap = extractImports();

		writeStatus(statusPath, "extracting", funcs.size(), 0, null);

		// Build call graph (calls_out + called_by) using call flow targets
		Map<String, LinkedHashSet<String>> callsOut = new HashMap<>();
		Map<String, LinkedHashSet<String>> calledBy = new HashMap<>();
		for (Function f : funcs) {
			callsOut.put(f.getName(), new LinkedHashSet<>());
			calledBy.put(f.getName(), new LinkedHashSet<>());
		}
		Listing listing0 = currentProgram.getListing();
		for (Function f : funcs) {
			InstructionIterator it = listing0.getInstructions(f.getBody(), true);
			while (it.hasNext()) {
				Instruction ins = it.next();
				try {
					FlowType ft = ins.getFlowType();
					if (ft == null || !ft.isCall()) continue;
					Address[] flows = ins.getFlows();
					if (flows == null) continue;
					for (Address to : flows) {
						if (to == null) continue;
						Function callee = fm.getFunctionAt(to);
						if (callee == null) callee = fm.getFunctionContaining(to);
						if (callee == null) continue;
						String calleeName = callee.getName();
						if (calleeName == null) continue;
						if (calleeName.equals(f.getName())) continue; // self-call handled in UI
						callsOut.get(f.getName()).add(calleeName);
					}
				} catch (Exception e) {
					// ignore
				}
			}
		}
		// Invert to called_by
		for (Map.Entry<String, LinkedHashSet<String>> e : callsOut.entrySet()) {
			String caller = e.getKey();
			for (String callee : e.getValue()) {
				if (!calledBy.containsKey(callee)) continue;
				calledBy.get(callee).add(caller);
			}
		}

		// entry point
		// Entry point: best-effort using external entry points
		Address ep = null;
		try {
			Iterator<Address> it = currentProgram.getSymbolTable().getExternalEntryPointIterator();
			if (it != null && it.hasNext()) {
				ep = it.next();
			}
		} catch (Exception e) {
			// ignore
		}

		Function defaultFunc = null;
		String reason = "fallback_none";
		if (ep != null) {
			defaultFunc = fm.getFunctionContaining(ep);
			if (defaultFunc != null) reason = "entry_point";
			else {
				defaultFunc = fm.getFunctionAt(ep);
				if (defaultFunc != null) reason = "entry_point_at";
			}
		}
		if (defaultFunc == null && !funcs.isEmpty()) {
			defaultFunc = funcs.get(0);
			reason = "fallback_first";
		}

		// Build JSON manually (small + stable)
		StringBuilder sb = new StringBuilder();
		sb.append("{\n");
		sb.append("  \"sample\": {\n");
		sb.append("    \"path\": ").append(jsonStr(currentProgram.getExecutablePath())).append(",\n");
		sb.append("    \"image_base\": ").append(jsonStr(addrStr(currentProgram.getImageBase()))).append(",\n");
		sb.append("    \"entry_point\": ").append(jsonStr(addrStr(ep))).append(",\n");
		sb.append("    \"format\": ").append(jsonStr(currentProgram.getExecutableFormat())).append(",\n");
		sb.append("    \"processor\": ").append(jsonStr(currentProgram.getLanguage().getProcessor().toString())).append(",\n");
		sb.append("    \"compiler\": ").append(jsonStr(currentProgram.getCompilerSpec().getCompilerSpecID().toString())).append("\n");
		sb.append("  },\n");
		sb.append("  \"ui\": {\n");
		sb.append("    \"default_function_id\": ").append(jsonStr(defaultFunc != null ? defaultFunc.getName() : null)).append(",\n");
		sb.append("    \"default_function_reason\": ").append(jsonStr(reason)).append("\n");
		sb.append("  },\n");

		// Extract defined strings (best-effort)
		List<Map<String, Object>> strings = new ArrayList<>();
		LinkedHashSet<String> seen = new LinkedHashSet<>();
		try {
			Listing lst = currentProgram.getListing();
			DataIterator dit = lst.getDefinedData(true);
			// NOTE: Can be large; keep a high safety cap to avoid runaway memory.
			int limit = 50000;
			int count = 0;
			while (dit.hasNext() && count < limit) {
				Data d = dit.next();
				if (d == null) continue;
				Object v = null;
				try { v = d.getValue(); } catch (Exception _e) { v = null; }
				if (!(v instanceof String)) continue;
				String s = (String)v;
				if (!looksLikeString(s)) continue;
				String addr = addrStr(d.getMinAddress());
				String key = addr + "|" + s;
				if (seen.contains(key)) continue;
				seen.add(key);
				Map<String, Object> row = new LinkedHashMap<>();
				row.put("addr", addr);
				row.put("value", s);
				row.put("len", s.length());
				row.put("type", d.getDataType() != null ? d.getDataType().getName() : null);
				strings.add(row);
				count++;
			}
		} catch (Exception e) {
			// ignore
		}

		// Build imports section
		sb.append("  \"imports\": [\n");
		Map<String, List<Map<String, String>>> importsByDll = new LinkedHashMap<>();
		for (Map.Entry<String, ImportInfo> e : importMap.entrySet()) {
			String apiName = e.getKey();
			ImportInfo info = e.getValue();
			String dllName = info.dll != null ? info.dll : "unknown";
			if (!importsByDll.containsKey(dllName)) {
				importsByDll.put(dllName, new ArrayList<>());
			}
			Map<String, String> api = new LinkedHashMap<>();
			api.put("name", apiName);
			api.put("address", info.address);
			importsByDll.get(dllName).add(api);
		}
		int dllIdx = 0;
		for (Map.Entry<String, List<Map<String, String>>> e : importsByDll.entrySet()) {
			String dllName = e.getKey();
			List<Map<String, String>> apis = e.getValue();
			sb.append("    {");
			sb.append("\"dll\":").append(jsonStr(dllName)).append(",");
			sb.append("\"apis\":[");
			for (int j = 0; j < apis.size(); j++) {
				Map<String, String> api = apis.get(j);
				sb.append("{");
				sb.append("\"name\":").append(jsonStr(api.get("name"))).append(",");
				sb.append("\"address\":").append(jsonStr(api.get("address")));
				sb.append("}");
				if (j != apis.size() - 1) sb.append(",");
			}
			sb.append("]}");
			if (dllIdx != importsByDll.size() - 1) sb.append(",");
			sb.append("\n");
			dllIdx++;
		}
		sb.append("  ],\n");

		sb.append("  \"strings\": [\n");
		for (int i = 0; i < strings.size(); i++) {
			Map<String, Object> row = strings.get(i);
			String addr = (String)row.get("addr");
			String val = (String)row.get("value");
			Integer len = (Integer)row.get("len");
			String type = (String)row.get("type");
			sb.append("    {");
			sb.append("\"addr\":").append(jsonStr(addr)).append(",");
			sb.append("\"value\":").append(jsonStr(val)).append(",");
			sb.append("\"len\":").append(len != null ? len.intValue() : 0).append(",");
			sb.append("\"type\":").append(jsonStr(type));
			sb.append("}");
			if (i != strings.size() - 1) sb.append(",");
			sb.append("\n");
		}
		sb.append("  ],\n");

		sb.append("  \"functions\": [\n");

		for (int i = 0; i < funcs.size(); i++) {
			Function f = funcs.get(i);
			long nowMs = System.currentTimeMillis();
			if (nowMs - lastStatusWriteMs > 1000) {
				lastStatusWriteMs = nowMs;
				writeStatus(statusPath, "extracting", funcs.size(), i, f.getName());
			}
			try {
				writeDisasm(f, disasmDir);
			} catch (Exception e) {
				// continue
			}
			try {
				writeDecompAndPcode(ifc, f, decompDir, pcodeDir);
			} catch (Exception e) {
				// continue
			}
			
			// Determine external/winapi/thunk flags
			String fname = f.getName();
			boolean isExternal = false;
			boolean isWinApi = false;
			boolean isThunk = false;
			String dll = null;
			
			// Case 1: Direct match in import map
			if (importMap.containsKey(fname)) {
				ImportInfo imp = importMap.get(fname);
				isExternal = true;
				isWinApi = imp.isWinApi;
				dll = imp.dll;
				try {
					isThunk = f.isThunk();
				} catch (Exception e) {}
			}
			// Case 2: Thunk function check
			else {
				try {
					if (f.isThunk()) {
						isThunk = true;
						isExternal = true;
						// Try to extract DLL from name (e.g., "kernel32.dll_CreateFileA")
						if (fname.contains(".dll_") || fname.contains(".DLL_")) {
							int idx = fname.indexOf(".dll_");
							if (idx < 0) idx = fname.indexOf(".DLL_");
							if (idx >= 0) {
								dll = fname.substring(0, idx + 4);
								isWinApi = isWindowsDLL(dll);
							}
						}
						// Check if it's in import map by alternative name
						String cleanName = fname;
						if (fname.startsWith("__imp_")) cleanName = fname.substring(6);
						if (importMap.containsKey(cleanName)) {
							ImportInfo imp = importMap.get(cleanName);
							isWinApi = imp.isWinApi;
							dll = imp.dll;
						}
					}
				} catch (Exception e) {}
			}
			// Case 3: Explicit external flag
			if (!isExternal) {
				try {
					if (f.isExternal()) {
						isExternal = true;
					}
				} catch (Exception e) {}
			}
			
			long size = f.getBody().getNumAddresses();
			sb.append("    {");
			sb.append("\"id\":").append(jsonStr(f.getName())).append(",");
			sb.append("\"name\":").append(jsonStr(f.getName())).append(",");
			sb.append("\"entry\":").append(jsonStr(addrStr(f.getEntryPoint()))).append(",");
			sb.append("\"size\":").append(size).append(",");
			sb.append("\"is_external\":").append(isExternal).append(",");
			sb.append("\"is_winapi\":").append(isWinApi).append(",");
			sb.append("\"is_thunk\":").append(isThunk).append(",");
			sb.append("\"dll\":").append(jsonStr(dll)).append(",");
			// calls_out
			sb.append("\"calls_out\":[");
			LinkedHashSet<String> outs = callsOut.get(f.getName());
			if (outs != null) {
				int k = 0;
				for (String callee : outs) {
					if (k++ > 0) sb.append(",");
					sb.append(jsonStr(callee));
				}
			}
			sb.append("],");
			// called_by
			sb.append("\"called_by\":[");
			LinkedHashSet<String> ins = calledBy.get(f.getName());
			if (ins != null) {
				int k2 = 0;
				for (String caller : ins) {
					if (k2++ > 0) sb.append(",");
					sb.append(jsonStr(caller));
				}
			}
			sb.append("]");
			sb.append("}");
			if (i != funcs.size() - 1) sb.append(",");
			sb.append("\n");
		}
		sb.append("  ]\n");
		sb.append("}\n");

		analysisPath.getParentFile().mkdirs();
		try (Writer w = new OutputStreamWriter(new FileOutputStream(analysisPath), "UTF-8")) {
			w.write(sb.toString());
		}

		writeStatus(statusPath, "done", funcs.size(), funcs.size(), null);
	}

	private static String jsonStr(String s) {
		if (s == null) return "null";
		String esc = s
			.replace("\\", "\\\\")
			.replace("\"", "\\\"")
			.replace("\n", "\\n")
			.replace("\r", "\\r")
			.replace("\t", "\\t");
		return "\"" + esc + "\"";
	}
}
