// ExtractStringReferences.java
// Extract inline string literals from decompiled C code using regex
//@author clawd
//@category AutoRE

import java.io.*;
import java.util.*;
import java.util.regex.*;

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;

public class ExtractStringReferences extends GhidraScript {

	private static String jsonEsc(String s) {
		if (s == null) return null;
		return s
			.replace("\\", "\\\\")
			.replace("\"", "\\\"")
			.replace("\n", "\\n")
			.replace("\r", "\\r")
			.replace("\t", "\\t");
	}

	private static String jsonStr(String s) {
		if (s == null) return "null";
		String esc = jsonEsc(s);
		return "\"" + esc + "\"";
	}

	private static boolean looksLikeString(String s) {
		if (s == null) return false;
		String t = s.trim();
		if (t.length() < 1) return false;
		if (t.length() > 4096) return false;
		int printable = 0;
		for (int i = 0; i < t.length(); i++) {
			char c = t.charAt(i);
			if (c == '\n' || c == '\r' || c == '\t') { printable++; continue; }
			if (c >= 0x20 && c <= 0x7e) printable++;
		}
		return printable >= (int)(t.length() * 0.7);
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 1) {
			println("ExtractStringReferences requires args: <output.json>");
			return;
		}

		File outputPath = new File(args[0]);

		FunctionManager fm = currentProgram.getFunctionManager();

		// Decompiler interface
		DecompInterface ifc = new DecompInterface();
		ifc.setOptions(new DecompileOptions());
		ifc.toggleCCode(true);
		ifc.openProgram(currentProgram);

		// Regex pattern to match string literals: "..." (C-style)
		// Handles escaped quotes: \"
		Pattern stringPattern = Pattern.compile("\"([^\"\\\\]*(?:\\\\.[^\"\\\\]*)*)\"");

		// Collect all string literals
		Map<String, Map<String, Object>> stringMap = new LinkedHashMap<>();
		LinkedHashSet<String> seen = new LinkedHashSet<>();

		try {
			FunctionIterator fit = fm.getFunctions(true);
			int funcCount = 0;
			int stringCount = 0;

			while (fit.hasNext()) {
				Function f = fit.next();
				if (f == null) continue;
				funcCount++;

				// Decompile function
				DecompileResults res = null;
				try {
					res = ifc.decompileFunction(f, 30, monitor);
				} catch (Exception e) {
					// Skip on decompile error
					continue;
				}

				if (res == null || !res.decompileCompleted()) continue;

				// Extract C code
				String cCode = "";
				try {
					DecompiledFunction df = res.getDecompiledFunction();
					if (df != null) {
						cCode = df.getC();
					}
				} catch (Exception e) {
					// Skip
					continue;
				}

				if (cCode == null || cCode.isEmpty()) continue;

				// Find all string literals using regex
				Matcher m = stringPattern.matcher(cCode);
				while (m.find()) {
					String literal = m.group(1);
					
					// Unescape C string escapes
					literal = literal
						.replace("\\\"", "\"")
						.replace("\\\\", "\\")
						.replace("\\n", "\n")
						.replace("\\r", "\r")
						.replace("\\t", "\t");

					if (!looksLikeString(literal)) continue;

					String key = f.getName() + "|" + literal;
					if (seen.contains(key)) continue;
					seen.add(key);

					Map<String, Object> entry = new LinkedHashMap<>();
					entry.put("value", literal);
					entry.put("len", literal.length());
					entry.put("in_function", f.getName());
					entry.put("source", "decompiled_code");

					stringMap.put(key, entry);
					stringCount++;
				}
			}

			println("Processed " + funcCount + " functions, found " + stringCount + " string literals");
		} catch (Exception e) {
			println("Error: " + e.toString());
			e.printStackTrace();
		} finally {
			ifc.closeProgram();
		}

		// Write JSON output
		StringBuilder sb = new StringBuilder();
		sb.append("{\n");
		sb.append("  \"string_references\": [\n");

		List<Map<String, Object>> entries = new ArrayList<>(stringMap.values());
		for (int i = 0; i < entries.size(); i++) {
			Map<String, Object> e = entries.get(i);
			sb.append("    {");
			sb.append("\"value\":").append(jsonStr((String)e.get("value"))).append(",");
			sb.append("\"len\":").append(e.get("len")).append(",");
			sb.append("\"in_function\":").append(jsonStr((String)e.get("in_function"))).append(",");
			sb.append("\"source\":").append(jsonStr((String)e.get("source")));
			sb.append("}");
			if (i != entries.size() - 1) sb.append(",");
			sb.append("\n");
		}

		sb.append("  ],\n");
		sb.append("  \"total_count\": ").append(stringMap.size()).append("\n");
		sb.append("}\n");

		outputPath.getParentFile().mkdirs();
		try (Writer w = new OutputStreamWriter(new FileOutputStream(outputPath), "UTF-8")) {
			w.write(sb.toString());
		}

		println("Extracted " + stringMap.size() + " string literals to: " + outputPath.getAbsolutePath());
	}
}
