// A tool to help sync reveresed info across teams
// @author Outer Cloud
// @category Collaboration
// @menupath Tools.ReSync.Pull
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
import com.google.gson.JsonObject;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.JsonElement;
import com.google.gson.JsonArray;
import java.util.Map;
import java.util.Set;
import java.io.FileReader;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;

public class ReSync extends GhidraScript {
    private JsonArray getFunctionData(String folderPath) throws IOException, FileNotFoundException {
        Gson gson = new Gson();

        FileReader reader = new FileReader(folderPath + "/functions.json");

        JsonArray data = gson.fromJson(reader, JsonArray.class);

        reader.close();

        return data;
    }

    private void loadRepository(String folderPath) {
        String repo = "<ENTER URL HERE>";

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

        for (JsonElement value : functionData) {
            JsonObject jsonObject = value.getAsJsonObject();

            long address = jsonObject.get("address").getAsLong();
            String symbol = jsonObject.get("symbol").getAsString();

            long effectiveAddress = baseAddressOffset + address;

            // println(effectiveAddress + " " + symbol);

            Address ghidraAddress = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(effectiveAddress);
            Function function = functionManager.getFunctionAt(ghidraAddress);

            if(function == null) {
                println("Null function " + symbol + " at " + Long.toHexString(effectiveAddress));

                continue;
            }

            try {
                DemangledObject demangled = DemanglerUtil.demangle(currentProgram, symbol);

                listing.setComment(ghidraAddress, CodeUnit.PLATE_COMMENT, symbol);

                if (demangled != null) {
                    String name = demangled.getName();
                    String signature = demangled.getSignature(false);

                    listing.setComment(ghidraAddress, CodeUnit.PLATE_COMMENT, symbol + "\n\n" + signature);
                    bookmarkManager.setBookmark(ghidraAddress, "Info", "Symbols", name);
                    function.setName(name, SourceType.USER_DEFINED);
                } else {
                    bookmarkManager.setBookmark(ghidraAddress, "Info", "Symbols", symbol);
                    function.setName(symbol, SourceType.USER_DEFINED);
                }
            } catch(Exception exception) {
                println("Error setting name " + symbol + " at " + Long.toHexString(effectiveAddress));
            }
        }
    }
}