// ExtractStringReferences.java
// Extract STRING REFERENCES (including inline strings) from all code
//@author clawd
//@category AutoRE

import java.io.*;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.reference.*;
import ghidra.program.model.symbol.RefType;

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

		ReferenceManager refMgr = currentProgram.getReferenceManager();
		FunctionManager fm = currentProgram.getFunctionManager();
		Listing listing = currentProgram.getListing();

		// Collect all string references
		Map<String, Map<String, Object>> stringMap = new LinkedHashMap<>();
		LinkedHashSet<String> seen = new LinkedHashSet<>();

		try {
			// Iterate all instructions/data in the program
			AddressSet addrSet = new AddressSet(currentProgram.getMinAddress(), currentProgram.getMaxAddress());
			AddressIterator addrIter = addrSet.getAddresses(true);

			int count = 0;
			int limit = 1000000; // Safety cap

			while (addrIter.hasNext() && count < limit) {
				Address addr = addrIter.next();
				if (addr == null) continue;

				try {
					// Get references FROM this address
					Reference[] refs = refMgr.getReferencesFrom(addr);
					if (refs == null || refs.length == 0) continue;

					// Check each reference
					for (Reference ref : refs) {
						if (ref == null) continue;

						// Only care about string references
						// String refs are typically READ refs to data section
						RefType rt = ref.getReferenceType();
						if (rt == null) continue;

						// Check if target looks like a string
						Address toAddr = ref.getToAddress();
						if (toAddr == null) continue;

						// Try to read string at target address
						String stringValue = null;
						try {
							// Get data at target
							Data d = listing.getDataAt(toAddr);
							if (d != null) {
								Object v = d.getValue();
								if (v instanceof String) {
									stringValue = (String)v;
								}
							}
						} catch (Exception e) {
							// Try manual read
						}

						if (stringValue == null || !looksLikeString(stringValue)) {
							continue;
						}

						// Found a string reference!
						String key = toAddr.toString() + "|" + stringValue;
						if (seen.contains(key)) continue;
						seen.add(key);

						// Get function containing this instruction
						Function containingFunc = fm.getFunctionContaining(addr);
						String funcName = containingFunc != null ? containingFunc.getName() : "unknown";

						// Store in map
						Map<String, Object> entry = new LinkedHashMap<>();
						entry.put("addr", toAddr.toString());
						entry.put("value", stringValue);
						entry.put("len", stringValue.length());
						entry.put("referenced_from", addr.toString());
						entry.put("in_function", funcName);
						entry.put("ref_type", rt.getName());

						stringMap.putIfAbsent(toAddr.toString(), entry);
						count++;
					}
				} catch (Exception e) {
					// Skip on error
				}
			}
		} catch (Exception e) {
			println("Error iterating addresses: " + e.toString());
		}

		// Write JSON output
		StringBuilder sb = new StringBuilder();
		sb.append("{\n");
		sb.append("  \"string_references\": [\n");

		List<Map<String, Object>> entries = new ArrayList<>(stringMap.values());
		for (int i = 0; i < entries.size(); i++) {
			Map<String, Object> e = entries.get(i);
			sb.append("    {");
			sb.append("\"addr\":").append(jsonStr((String)e.get("addr"))).append(",");
			sb.append("\"value\":").append(jsonStr((String)e.get("value"))).append(",");
			sb.append("\"len\":").append(e.get("len")).append(",");
			sb.append("\"referenced_from\":").append(jsonStr((String)e.get("referenced_from"))).append(",");
			sb.append("\"in_function\":").append(jsonStr((String)e.get("in_function"))).append(",");
			sb.append("\"ref_type\":").append(jsonStr((String)e.get("ref_type")));
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

		println("Extracted " + stringMap.size() + " string references to: " + outputPath.getAbsolutePath());
	}
}
