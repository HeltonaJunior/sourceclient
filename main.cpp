/*
 * Copyright (c) 2010-2017 OTClient <https://github.com/edubart/otclient>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <framework/core/application.h>
#include <framework/core/resourcemanager.h>
#include <framework/core/eventdispatcher.h>
#include <framework/luaengine/luainterface.h>
#include <framework/http/http.h>
#include <framework/platform/crashhandler.h>
#include <framework/platform/platformwindow.h>
#include <client/client.h>
#include <client/game.h>

#define PHYSFS_DEPRECATED
#include <physfs.h>

// Enhanced Encryption System
#define DEF_DEFINITION
#define LAUNCHER_SECRET "1A2B3C4D5E6F7G8H9I0J1K2L3"

int main(int argc, const char* argv[]) {
    std::vector<std::string> args(argv, argv + argc);

    // Initialize logger early for diagnostic messages
    g_logger.setLogFile("otclient_startup.log");
    //g_logger.info("=== OTCLIENT STARTUP ===");
    //g_logger.info(stdext::format("Starting OTClient with %d arguments", argc));
    
    // Log all arguments for debugging
    for (int i = 0; i < argc; i++) {
        //g_logger.info(stdext::format("arg[%d]: %s", i, argv[i]));
    }

#ifdef DEF_DEFINITION
    //g_logger.info("DEF_DEFINITION is active - checking launcher authentication");
    
    // Verify launcher authentication secret
    bool hasLauncherSecret = false;
    for (const auto& arg : args) {
        if (arg == LAUNCHER_SECRET) {
            hasLauncherSecret = true;
            //g_logger.info("Launcher secret found - authentication OK");
            break;
        }
    }
    
    if (!hasLauncherSecret) {
#ifdef ANDROID
        // Android build: bypass launcher authentication
        g_logger.info("Android build detected - bypassing launcher authentication");
        g_logger.info("Launcher secret check disabled for Android compatibility");
#else
        // Client requires launcher authentication when DEF_DEFINITION is active
        g_logger.error("LAUNCHER SECRET NOT FOUND!");
        g_logger.error(stdext::format("Expected: %s", LAUNCHER_SECRET));
        g_logger.error("Client will exit with code -1");
        g_logger.error("Please launch the client through the official launcher");
        
#ifdef WIN32
        // Show error message to user on Windows
        std::string errorMsg = "ERRO DE SEGURAN\u00C7A\n\n";
        errorMsg += "Este cliente possui prote\u00E7\u00E3o avan\u00E7ada e deve ser executado\n";
        errorMsg += "exclusivamente atrav\u00E9s do Launcher oficial.\n\n";
        errorMsg += "Por favor, execute o jogo usando o Launcher oficial\n";
        errorMsg += "para garantir a seguran\u00E7a e integridade do sistema.";
        
        MessageBoxA(NULL, errorMsg.c_str(), "PokeAsil - Erro de Autentica\u00E7\u00E3o", MB_OK | MB_ICONERROR | MB_TOPMOST);
#endif
        
        return -1;
#endif
    }
#else
    //g_logger.info("DEF_DEFINITION is disabled - skipping launcher authentication");
#endif

#ifdef CRASH_HANDLER
    installCrashHandler();
    //g_logger.info("Crash handler installed");
#endif

    // initialize resources
    g_resources.init(argv[0]);
    std::string compactName = g_resources.getCompactName();

    // setup application name and version
    g_app.setName("OTClientV8");
    g_app.setCompactName(compactName);
    g_app.setVersion("3.2");

#ifdef WITH_ENCRYPTION
    if (std::find(args.begin(), args.end(), "--encrypt") != args.end()) {
        //g_logger.info("Encryption mode detected");
        g_lua.init();
        g_resources.encrypt(args.size() >= 3 ? args[2] : "");
        std::cout << "Encryption complete" << std::endl;
#ifdef WIN32
        MessageBoxA(NULL, "Encryption complete", "Success", 0);
#endif
        return 0;
    }
#endif

    if (g_resources.launchCorrect(g_app.getName(), g_app.getCompactName())) {
        g_logger.info("Launch correction triggered - starting other executable");
        return 0; // started other executable
    }

    // initialize application framework and otclient
    g_app.init(args);
    g_client.init(args);
    //g_logger.info("Initializing HTTP...");
    g_http.init();

#ifdef DEF_DEFINITION
    // Force disable debug/terminal features at engine level
    g_game.enableFeature(Otc::GameNoDebug);
#endif

    bool testMode = std::find(args.begin(), args.end(), "--test") != args.end();
    if (testMode) {
        //g_logger.info("Test mode enabled");
        g_logger.setTestingMode();    
    }

    // find script init.lua and run it
    //g_logger.info("Setting up write directory...");
    if (!g_resources.setupWriteDir(g_app.getName(), g_app.getCompactName())) {
        g_logger.fatal("Failed to setup write directory - cannot save configurations");
    }
    
    // Verify write directory is accessible
    const char* writeDir = PHYSFS_getWriteDir();
    if (writeDir) {
        g_logger.info(stdext::format("Write directory set to: %s", writeDir));
    } else {
        g_logger.error("Write directory is NULL after setup");
    }
    
    //g_logger.info("Setting up resources...");
    g_resources.setup();
    
    // Test config save functionality after everything is set up
    if (!g_resources.testConfigSave()) {
        g_logger.error("Config save test failed - configurations may not persist");
    }
    
    // Test config path resolution specifically  
    // g_resources.testConfigLoadSave(); // Temporarily disabled

    //g_logger.info("Attempting to run init script...");
    bool initSuccess = false;
    
    // Debug: Check what files exist in the current directory
    //g_logger.info("=== DEBUG: Checking available files ===");
    //g_logger.info(stdext::format("init.lua.enc exists: %s", PHYSFS_exists("init.lua.enc") ? "YES" : "NO"));
    //g_logger.info(stdext::format("init.lua exists: %s", PHYSFS_exists("init.lua") ? "YES" : "NO"));
    
    // List all files in root directory
    char **fileList = PHYSFS_enumerateFiles("/");
    //g_logger.info("=== All files in root directory: ===");
    for (char **i = fileList; *i != NULL; i++) {
        //g_logger.info(stdext::format("File: %s", *i));
        // Also check if it's a directory
        if (PHYSFS_isDirectory(*i)) {
            //g_logger.info(stdext::format("  -> %s is a directory", *i));
        }
    }
    PHYSFS_freeList(fileList);
    
    // Get current working directory for debugging
    const char* workDir = PHYSFS_getWriteDir();
    const char* baseDir = PHYSFS_getBaseDir();
    //g_logger.info(stdext::format("PHYSFS Write Dir: %s", workDir ? workDir : "NULL"));
    //g_logger.info(stdext::format("PHYSFS Base Dir: %s", baseDir ? baseDir : "NULL"));
    
    // Try to run init.lua - the ENCX system will automatically resolve to init.lua.enc if it exists
    //g_logger.info("=== ATTEMPTING TO RUN init.lua ===");
    //g_logger.info("Note: ENCX system will automatically try init.lua.enc if DEF_DEFINITION is active");
    initSuccess = g_lua.safeRunScript("init.lua");
    //g_logger.info(stdext::format("init.lua execution result: %s", initSuccess ? "SUCCESS" : "FAILED"));
    
    if (!initSuccess) {
        g_logger.error("=== INIT SCRIPT EXECUTION FAILED ===");
        g_logger.error("Failed to run init script - trying fallback methods");
        if (g_resources.isLoadedFromArchive() && !g_resources.isLoadedFromMemory() &&
            g_resources.loadDataFromSelf(true)) {
            g_logger.error("Unable to run script init.lua! Trying to run version from memory.");
            if (!g_lua.safeRunScript("init.lua")) {
                g_resources.deleteFile("data.zip"); // remove incorrect data.zip
                g_logger.fatal("Unable to run script init.lua from binary file!\nTry to run client again.");
            }
        } else {
            g_logger.fatal("Unable to run script init.lua!");
        }
    } else {
        //g_logger.info("=== INIT SCRIPT EXECUTION SUCCESSFUL ===");
    }

    if (testMode) {
        //g_logger.info("Running test.lua...");
        if (!g_lua.safeRunScript("test.lua")) {
            g_logger.fatal("Can't run test.lua");
        }
    }

#ifdef WIN32
    // support for progdn proxy system, if you don't have this dll nothing will happen
    // however, it is highly recommended to use otcv8 proxy system
    //g_logger.info("Loading progdn32.dll if available...");
    LoadLibraryA("progdn32.dll");
#endif

    // the run application main loop
    //g_logger.info("Starting main application loop...");
    g_app.run();
    //g_logger.info("Main application loop ended");

#ifdef CRASH_HANDLER
    //g_logger.info("Uninstalling crash handler...");
    uninstallCrashHandler();
#endif

    // unload modules
    //g_logger.info("Deinitializing application...");
    g_app.deinit();

    // terminate everything and free memory
    //g_logger.info("Terminating components...");
    g_http.terminate();
    g_client.terminate();
    g_app.terminate();
    //g_logger.info("=== OTCLIENT SHUTDOWN COMPLETE ===");
    return 0;
}

#ifdef ANDROID
#include <framework/platform/androidwindow.h>

android_app* g_androidState = nullptr;
void android_main(struct android_app* state)
{
    g_mainThreadId = g_dispatcherThreadId = g_graphicsThreadId = std::this_thread::get_id();
    g_androidState = state;

    state->userData = nullptr;
    state->onAppCmd = +[](android_app* app, int32_t cmd) -> void {
       return g_androidWindow.handleCmd(cmd);
    };
    state->onInputEvent = +[](android_app* app, AInputEvent* event) -> int32_t {
        return g_androidWindow.handleInput(event);
    };
    state->activity->callbacks->onNativeWindowResized = +[](ANativeActivity* activity, ANativeWindow* window) -> void {
        g_graphicsDispatcher.scheduleEventEx("updateWindowSize", [] {
            g_androidWindow.updateSize();
        }, 500);
    };
    state->activity->callbacks->onContentRectChanged = +[](ANativeActivity* activity, const ARect* rect) -> void {
        g_graphicsDispatcher.scheduleEventEx("updateWindowSize", [] {
            g_androidWindow.updateSize();
        }, 500);
    };

    bool terminated = false;
    g_window.setOnClose([&] {
        terminated = true;
    });
    while(!g_window.isVisible() && !terminated)
        g_window.poll(); // init window
    // run app
    const char* args[] = { "otclientv8.apk" };
    main(1, args);
    std::exit(0); // required!
}
#endif
