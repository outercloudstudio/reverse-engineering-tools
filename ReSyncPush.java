// A tool to help sync reveresed info across teams
// @author Outer Cloud
// @category Collaboration
// @menupath Tools.ReSync.Push
// @toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import java.net.URL;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.stream.Collectors;
import java.io.File;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.nio.file.Files;
import java.nio.file.Path;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.JsonElement;
import com.google.gson.JsonArray;
import java.util.Map;
import java.util.Set;
import java.io.FileReader;
import java.io.FileWriter;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Symbol;

public class ReSyncPush extends GhidraScript {
    private JsonArray getFunctionData(String folderPath) throws IOException, FileNotFoundException {
        Gson gson = new Gson();

        FileReader reader = new FileReader(folderPath + "/functions.json");

        JsonArray data = gson.fromJson(reader, JsonArray.class);

        reader.close();

        return data;
    }

    private String convertIndents(String jsonString) {
        String[] lines = jsonString.split("\n");
        StringBuilder result = new StringBuilder();

        for (String line : lines) {
            int leadingSpaces = 0;
            for (int i = 0; i < line.length(); i++) {
                if (line.charAt(i) == ' ') {
                    leadingSpaces++;
                } else {
                    break;
                }
            }
            
            StringBuilder indent = new StringBuilder();
            for (int i = 0; i < leadingSpaces * 2; i++) {
                indent.append(' ');
            }
            
            result.append(indent).append(line.trim()).append("\n");
        }

        return result.toString();
    }

    private void updateFunctions(String folderPath, JsonArray functionData) throws IOException, FileNotFoundException {
        try (FileWriter writer = new FileWriter(folderPath + "/functions.json")) {
            Gson gson = new GsonBuilder().setPrettyPrinting().create();

            writer.write(convertIndents(gson.toJson(functionData)));
        }
    }

    private void loadRepository(String folderPath) {
        String repo = "<ENTER REPO HERE>";

        File folder = new File(folderPath);
        folder.mkdirs();

        File gitDir = new File(folderPath, ".git");

        if (!gitDir.isDirectory()) {
            println("Cloning repository into " + folderPath + "...");

            try {
                ProcessBuilder pb = new ProcessBuilder("git", "clone", repo, folderPath);
                pb.inheritIO();
                Process process = pb.start();
                int exitCode = process.waitFor();

                if (exitCode != 0) {
                    println("Error cloning repository: exit code " + exitCode);
                    return;
                }
            } catch (IOException | InterruptedException e) {
                println("Error cloning repository: " + e.getMessage());
                e.printStackTrace();
                return;
            }
        }
    }

    private void commitChanges(String folderPath, String message) {
        try {
            ProcessBuilder pb = new ProcessBuilder("git", "-C", folderPath, "commit", "-a", "-m", message);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            
            String line= "";
            while ((line = reader.readLine()) != null) {
                println(line);
            }
            
            process.waitFor();

            pb = new ProcessBuilder("git", "-C", folderPath, "push");
            pb.redirectErrorStream(true);
            process = pb.start();
            
            reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            
            line= "";
            while ((line = reader.readLine()) != null) {
                println(line);
            }
            
            process.waitFor();
        } catch (IOException | InterruptedException e) {
            println("Error pushing changes: " + e.getMessage());
            e.printStackTrace();
            return;
        }
    }

    private String demangleName(String symbol, Program currentProgram) {
        try {
            DemangledObject demangled = DemanglerUtil.demangle(currentProgram, symbol);

            if (demangled != null) {
                return demangled.getName();
            }
        } catch(Exception exception) {}

        return symbol;
    }

    private String demangleSignature(String symbol, Program currentProgram) {
        try {
            DemangledObject demangled = DemanglerUtil.demangle(currentProgram, symbol);

            if (demangled != null) {
                return demangled.getSignature(false);
            }
        } catch(Exception exception) {}

        return "Could not demangle signature";
    }

    @Override
    public void run() throws Exception {
        Program currentProgram = getCurrentProgram();
        String programName = currentProgram.getName();

        String appData = System.getenv("APPDATA");
        String folderPath = appData + "/Amethyst/tools/re-sync/" + programName;

        loadRepository(folderPath);

        Gson gson = new Gson();

        JsonArray functionData = getFunctionData(folderPath);

        Address baseAddress = currentProgram.getImageBase();
        long baseAddressOffset = baseAddress.getOffset();

        println("Base Address Offset: " + baseAddressOffset);

        FunctionManager functionManager = currentProgram.getFunctionManager();
        BookmarkManager bookmarkManager = currentProgram.getBookmarkManager();
        Listing listing = currentProgram.getListing();

        FunctionIterator functions = listing.getFunctions(true);
        
        for (Function function : functions) {
            String name = function.getName();
            Symbol symbol = function.getSymbol();
            Long relativeOffset = function.getEntryPoint().getOffset() - baseAddressOffset;

            if(symbol.getSource() == SourceType.DEFAULT || symbol.getSource() == SourceType.ANALYSIS) {
                continue;
            }

            int existingIndex = -1;

            for(int index = 0; index < functionData.size(); index++) {
                JsonElement value = functionData.get(index);
                JsonObject jsonObject = value.getAsJsonObject();

                long otherAddress = jsonObject.get("address").getAsLong();
                String otherSymbol = jsonObject.get("symbol").getAsString();

                if (otherAddress == relativeOffset) {
                    existingIndex = index;

                    break;
                }
            }

            if(existingIndex == -1) {
                println("New! " + existingIndex + " " + name);

                JsonObject entry = new JsonObject();
                entry.addProperty("address", relativeOffset);
                entry.addProperty("symbol", name);

                functionData.add(entry);
            } else {
                String comment = listing.getComment(CodeUnit.PLATE_COMMENT, function.getEntryPoint());

                if(comment == null || comment.isEmpty()) continue;

                String fullSymbol = comment.split("\n")[0];

                String demangledName = demangleName(fullSymbol, currentProgram);

                if(name.equals(demangledName)) continue;

                println("Renaming! " + existingIndex + " " + name);

                JsonObject entry = new JsonObject();
                entry.addProperty("address", relativeOffset);
                entry.addProperty("symbol", name);

                functionData.set(existingIndex, entry);
            }

            Address ghidraAddress = function.getEntryPoint();
            String demangledName = demangleName(name, currentProgram);
            String demangledSignature = demangleSignature(name, currentProgram);

            try {
                listing.setComment(ghidraAddress, CodeUnit.PLATE_COMMENT, name + "\n\n" + demangledSignature);
                bookmarkManager.setBookmark(ghidraAddress, "Info", "Symbols", demangledName);
                function.setName(demangledName, SourceType.USER_DEFINED);
            } catch(Exception exception) {
                println("Error setting name " + name);
            }
        }

        updateFunctions(folderPath, functionData);
        commitChanges(folderPath, "Updated Functions");
    }
}