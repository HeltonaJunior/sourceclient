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

#include "resourcemanager.h"
#include "filestream.h"
#include "resource.h"
#include <sstream>

#include <framework/core/application.h>
#include <framework/luaengine/luainterface.h>
#include <framework/platform/platform.h>
#include <framework/util/crypt.h>
#include <framework/http/http.h>
#include <queue>
#include <regex>

#if not(defined(ANDROID) || defined(FREE_VERSION))
#include <boost/process.hpp>
#endif
#include <locale>
#include <zlib.h>

#define PHYSFS_DEPRECATED
#include <physfs.h>
#ifndef __EMSCRIPTEN__
#include <zip.h>
#include <zlib.h>
#endif

ResourceManager g_resources;
static const std::string INIT_FILENAME = "init.lua";

void ResourceManager::init(const char *argv0)
{
#if defined(WIN32)
    char fileName[255];
    GetModuleFileNameA(NULL, fileName, sizeof(fileName));
    m_binaryPath = std::filesystem::absolute(fileName);
#elif defined(ANDROID)
    // nothing
#else
    m_binaryPath = std::filesystem::absolute(argv0);    
#endif
    PHYSFS_init(argv0);
    PHYSFS_permitSymbolicLinks(1);
}

void ResourceManager::terminate()
{
    PHYSFS_deinit();
}

bool ResourceManager::launchCorrect(const std::string& product, const std::string& app) { // curently works only on windows
#if not(defined(ANDROID) || defined(FREE_VERSION))
    auto init_path = m_binaryPath.parent_path();
    init_path /= INIT_FILENAME;
    if (std::filesystem::exists(init_path)) // debug version
        return false;

    const char* localDir = PHYSFS_getPrefDir(product.c_str(), app.c_str());
    if (!localDir)
        return false;

    auto fileName2 = m_binaryPath.stem().string();
    fileName2 = stdext::split(fileName2, "-")[0];
    stdext::tolower(fileName2);

    std::filesystem::path path(std::filesystem::u8path(localDir));
    std::error_code ec;
    auto lastWrite = std::filesystem::last_write_time(m_binaryPath, ec);
    std::filesystem::path binary = m_binaryPath;
    for (auto& entry : std::filesystem::directory_iterator(path)) {
        if (std::filesystem::is_directory(entry.path()))
            continue;

        auto fileName1 = entry.path().stem().string();
        fileName1 = stdext::split(fileName1, "-")[0];
        stdext::tolower(fileName1);
        if (fileName1 != fileName2)
            continue;

        if (entry.path().extension() == m_binaryPath.extension()) {
            std::error_code ec;
            auto writeTime = std::filesystem::last_write_time(entry.path(), ec);
            if (!ec && writeTime > lastWrite) {
                lastWrite = writeTime;
                binary = entry.path();
            }
        }
    }

    for (auto& entry : std::filesystem::directory_iterator(path)) { // remove old
        if (std::filesystem::is_directory(entry.path()))
            continue;

        auto fileName1 = entry.path().stem().string();
        fileName1 = stdext::split(fileName1, "-")[0];
        stdext::tolower(fileName1);
        if (fileName1 != fileName2)
            continue;

        if (entry.path().extension() == m_binaryPath.extension()) {
            if (binary == entry.path())
                continue;
            std::error_code ec;
            std::filesystem::remove(entry.path(), ec);
        }
    }

    if (binary == m_binaryPath)
        return false;

    boost::process::child c(binary.string());
    std::error_code ec2;
    if (c.wait_for(std::chrono::seconds(5), ec2)) {
        return c.exit_code() == 0;
    }

    c.detach();
    return true;
#else
    return false;
#endif
}

bool ResourceManager::setupWriteDir(const std::string& product, const std::string& app) {
#ifdef ANDROID
    const char* localDir = g_androidState->activity->internalDataPath;
#else
    const char* localDir = PHYSFS_getPrefDir(product.c_str(), app.c_str());
#endif

    if (!localDir) {
        g_logger.fatal(stdext::format("Unable to get local dir, error: %s", PHYSFS_getErrorByCode(PHYSFS_getLastErrorCode())));
        return false;
    }

    if (!PHYSFS_mount(localDir, NULL, 0)) {
        g_logger.fatal(stdext::format("Unable to mount local directory '%s': %s", localDir, PHYSFS_getErrorByCode(PHYSFS_getLastErrorCode())));
        return false;
    }

    if (!PHYSFS_setWriteDir(localDir)) {
        g_logger.fatal(stdext::format("Unable to set write dir '%s': %s", localDir, PHYSFS_getErrorByCode(PHYSFS_getLastErrorCode())));
        return false;
    }

#ifndef ANDROID
    m_writeDir = std::filesystem::path(std::filesystem::u8path(localDir));
#endif
    return true;
}

bool ResourceManager::setup()
{
    //g_logger.info("ResourceManager::setup() - Starting Android setup");
    
    std::shared_ptr<std::vector<uint8_t>> data = nullptr;
#ifdef ANDROID
    // Sempre tenta primeiro carregar do APK (assets) via AAssetManager
    if (loadDataFromSelf()) {
        return true; // data.zip montado da APK, UI/módulos OK
    }

    // Fallback: tentar via PHYSFS_openRead("data.zip") (nem sempre enxerga assets)
    PHYSFS_File* file = PHYSFS_openRead("data.zip");
    if (file) {
        auto data = std::make_shared<std::vector<uint8_t>>(PHYSFS_fileLength(file));
        PHYSFS_readBytes(file, data->data(), data->size());
        PHYSFS_close(file);
        if (mountMemoryData(data)) {
            return true;
        } else {
            g_logger.error("ResourceManager::setup() - Failed to mount data.zip (PHYSFS fallback)");
        }
    } else {
        g_logger.error("ResourceManager::setup() - data.zip not found (PHYSFS fallback)");
    }
#else
    std::string localDir(PHYSFS_getWriteDir());
    std::vector<std::string> possiblePaths = { localDir, g_platform.getCurrentDir() };
    const char* baseDir = PHYSFS_getBaseDir();
    if (baseDir)
        possiblePaths.push_back(baseDir);

    for (const std::string& dir : possiblePaths) {
        if (dir == localDir || !PHYSFS_mount(dir.c_str(), NULL, 0))
            continue;

        bool hasInitFile = false;
        
        // Check for init.lua first
        if(PHYSFS_exists(INIT_FILENAME.c_str())) {
            hasInitFile = true;
        }
        
#ifdef DEF_DEFINITION
        // If DEF_DEFINITION is active, also check for init.lua.enc
        if (!hasInitFile && PHYSFS_exists((INIT_FILENAME + ".enc").c_str())) {
            hasInitFile = true;
        }
#endif

        if (hasInitFile) {
            ////g_logger.info(stdext::format("Found work dir at '%s'", dir));
            return true;
        }

        PHYSFS_unmount(dir.c_str());
    }

    for(const std::string& dir : possiblePaths) {
        if (dir != localDir && !PHYSFS_mount(dir.c_str(), NULL, 0)) {
            continue;
        }

        if (!PHYSFS_exists("data.zip")) {
            if(dir != localDir)
                PHYSFS_unmount(dir.c_str());
            continue;
        }

        PHYSFS_File* file = PHYSFS_openRead("data.zip");
        if (!file) {
            if (dir != localDir)
                PHYSFS_unmount(dir.c_str());
            continue;
        }

        auto data = std::make_shared<std::vector<uint8_t>>(PHYSFS_fileLength(file));
        PHYSFS_readBytes(file, data->data(), data->size());
        PHYSFS_close(file);
        if (dir != localDir)
            PHYSFS_unmount(dir.c_str());

        ////g_logger.info(stdext::format("Found work dir at '%s'", dir));
        if (mountMemoryData(data))
            return true;
    }
#endif
    //g_logger.info("ResourceManager::setup() - Trying to load data from self");
    if (loadDataFromSelf()) {
        //g_logger.info("ResourceManager::setup() - Successfully loaded data from self");
        return true;
    }

    g_logger.error("ResourceManager::setup() - Failed to load data from self");
    g_logger.fatal("Unable to find working directory (or data.zip)");
    return false;
}

std::string ResourceManager::getCompactName() {
    std::string fileData;
    if (loadDataFromSelf()) {
        try {
            fileData = readFileContents(INIT_FILENAME);
        } catch (...) {
            fileData = "";
        }
        unmountMemoryData();
    }

#ifndef ANDROID
    std::vector<std::string> possiblePaths = { g_platform.getCurrentDir() };
    const char* baseDir = PHYSFS_getBaseDir();
    if (baseDir)
        possiblePaths.push_back(baseDir);

    if (fileData.empty()) {
        try {
            for (const std::string& dir : possiblePaths) {
                if (!PHYSFS_mount(dir.c_str(), NULL, 0))
                    continue;

                if (PHYSFS_exists(INIT_FILENAME.c_str())) {
                    fileData = readFileContents(INIT_FILENAME);
                    PHYSFS_unmount(dir.c_str());
                    break;
                }
                PHYSFS_unmount(dir.c_str());
            }
        } catch (...) {
            fileData = "";
        }
    }

    if (fileData.empty()) {
        try {
            for (const std::string& dir : possiblePaths) {
                std::string path = dir + "/data.zip";
                if (!PHYSFS_mount(path.c_str(), NULL, 0))
                    continue;

                if (PHYSFS_exists(INIT_FILENAME.c_str())) {
                    fileData = readFileContents(INIT_FILENAME);
                    PHYSFS_unmount(path.c_str());
                    break;
                }
                PHYSFS_unmount(path.c_str());
            }
        } catch (...) {}
    }
#endif

    std::smatch regex_match;
    if (std::regex_search(fileData, regex_match, std::regex("APP_NAME[^\"]+\"([^\"]+)"))) {
        if (regex_match.size() == 2 && regex_match[1].str().length() > 0 && regex_match[1].str().length() < 30) {
            return regex_match[1].str();
        }
    }
    return "otclientv8";
}

bool ResourceManager::loadDataFromSelf(bool unmountIfMounted) {
    //g_logger.info("ResourceManager::loadDataFromSelf() - Starting");
    
    std::shared_ptr<std::vector<uint8_t>> data = nullptr;
#ifdef ANDROID
    //g_logger.info("ResourceManager::loadDataFromSelf() - Android: Opening data.zip from assets");
    
    AAsset* file = AAssetManager_open(g_androidState->activity->assetManager, "data.zip", AASSET_MODE_BUFFER);
    if (!file) {
        g_logger.fatal("ResourceManager::loadDataFromSelf() - Can't open data.zip from assets");
        return false;
    }
    
    //g_logger.info("ResourceManager::loadDataFromSelf() - Android: data.zip opened successfully");
    data = std::make_shared<std::vector<uint8_t>>(AAsset_getLength(file));
    //g_logger.info(stdext::format("ResourceManager::loadDataFromSelf() - Android: data.zip size: %d bytes", data->size()));
    
    AAsset_read(file, data->data(), data->size());
    AAsset_close(file);
    //g_logger.info("ResourceManager::loadDataFromSelf() - Android: data.zip read successfully");
#else
    std::ifstream file(m_binaryPath.string(), std::ios::binary);
    if (!file.is_open())
        return false;
    file.seekg(0, std::ios_base::end);
    std::size_t size = file.tellg();
    file.seekg(0, std::ios_base::beg);
    if (size < 1024 || size > 1024 * 1024 * 128) {
        file.close();
        return false;
    }

    std::vector<uint8_t> v(1 + size);
    file.read((char*)&v[0], size);
    file.close();
    for (size_t i = 0, end = size - 128; i < end; ++i) {
        if (v[i] == 0x50 && v[i + 1] == 0x4b && v[i + 2] == 0x03 && v[i + 3] == 0x04 && v[i + 4] == 0x14) {
            uint32_t compSize = *(uint32_t*)&v[i + 18];
            uint32_t decompSize = *(uint32_t*)&v[i + 22];
            if (compSize < 1024 * 1024 * 512 && decompSize < 1024 * 1024 * 512) {
                data = std::make_shared<std::vector<uint8_t>>(&v[i], &v[v.size() - 1]);
                break;
            }
        }
    }
    v.clear();

#endif

    if (unmountIfMounted)
        unmountMemoryData();

    //g_logger.info("ResourceManager::loadDataFromSelf() - Attempting to mount memory data");
    if (mountMemoryData(data)) {
        //g_logger.info("ResourceManager::loadDataFromSelf() - Successfully mounted memory data");
        m_loadedFromMemory = true;
        return true;
    }

    g_logger.error("ResourceManager::loadDataFromSelf() - Failed to mount memory data");
    return false;
}

bool ResourceManager::fileExists(const std::string& fileName)
{
    if (fileName.find("/downloads") != std::string::npos)
        return g_http.getFile(fileName.substr(10)) != nullptr;
    return (PHYSFS_exists(resolvePath(fileName).c_str()) && !PHYSFS_isDirectory(resolvePath(fileName).c_str()));
}

bool ResourceManager::directoryExists(const std::string& directoryName)
{
    if (directoryName == "/downloads")
        return true;
    return (PHYSFS_isDirectory(resolvePath(directoryName).c_str()));
}

void ResourceManager::readFileStream(const std::string& fileName, std::iostream& out)
{
    std::string buffer(readFileContents(fileName));
    if(buffer.length() == 0) {
        out.clear(std::ios::eofbit);
        return;
    }
    out.clear(std::ios::goodbit);
    out.write(&buffer[0], buffer.length());
    out.seekg(0, std::ios::beg);
}

std::string ResourceManager::readFileContents(const std::string& fileName, bool safe)
{
    std::string fullPath = resolvePath(fileName);
    
    if (fullPath.find("/downloads") != std::string::npos) {
        auto dfile = g_http.getFile(fullPath.substr(10));
        if (dfile)
            return std::string(dfile->response.begin(), dfile->response.end());
    }

    PHYSFS_File* file = PHYSFS_openRead(fullPath.c_str());
    if(!file)
        stdext::throw_exception(stdext::format("unable to open file '%s': %s", fullPath, PHYSFS_getErrorByCode(PHYSFS_getLastErrorCode())));

    int fileSize = PHYSFS_fileLength(file);
    std::string buffer(fileSize, 0);
    PHYSFS_readBytes(file, (void*)&buffer[0], fileSize);
    PHYSFS_close(file);

    if (safe) {
        return buffer;
    }

    // skip decryption for bot configs
    if (fullPath.find("/bot/") != std::string::npos) {
        return buffer;
    }

#ifdef DEF_DEFINITION
    // ENCX System - Priority handling when DEF_DEFINITION is active
    if (buffer.size() >= 4 && buffer.substr(0, 4).compare("ENCX") == 0) {
        // Special debug for PNG files
        if (fileName.find(".png") != std::string::npos) {
            ////g_logger.info(stdext::format("[ENCX-DEBUG] Loading PNG with ENCX header: %s", fullPath));
        }
        
        // File has ENCX header - decrypt with ENCX
        if (!decryptBufferX(buffer)) {
#ifdef ANDROID
            g_logger.warning(stdext::format("unable to decrypt ENCX file (continuing anyway): %s", fullPath));
#else
            g_logger.fatal(stdext::format("unable to decrypt ENCX file: %s", fullPath));
#endif
        }
        
        if (fileName.find(".png") != std::string::npos) {
            ////g_logger.info(stdext::format("[ENCX-DEBUG] Successfully decrypted PNG: %s", fullPath));
        }
        
        return buffer;
    }
    
    // Check if file ends with .enc extension - decrypt with ENCX
    if (fileName.size() > 4 && fileName.substr(fileName.size() - 4) == ".enc") {
        // Special debug for PNG files
        if (fileName.find(".png") != std::string::npos) {
            ////g_logger.info(stdext::format("[ENCX-DEBUG] Loading .png.enc file: %s", fullPath));
        }
        
        if (!decryptBufferX(buffer)) {
#ifdef ANDROID
            g_logger.warning(stdext::format("unable to decrypt .enc file (continuing anyway): %s", fullPath));
#else
            g_logger.fatal(stdext::format("unable to decrypt .enc file: %s", fullPath));
#endif
        }
        
        if (fileName.find(".png") != std::string::npos) {
            ////g_logger.info(stdext::format("[ENCX-DEBUG] Successfully decrypted .png.enc: %s", fullPath));
        }
        
        return buffer;
    }
#endif

    static std::string unencryptedExtensions[] = { ".otml", ".otmm", ".dmp", ".log", ".txt", ".dll", ".exe", ".zip", ".dat", ".spr", ".otfi", ".cwm" };

    // Legacy ENC3 decryption for backwards compatibility
    if (!decryptBuffer(buffer)) {
        bool ignore = (m_customEncryption == 0);
        for (auto& it : unencryptedExtensions) {
            if (fileName.find(it) == fileName.size() - it.size()) {
                ignore = true;
            }
        }
#ifdef ANDROID
        // For Android builds, be more tolerant with decryption failures
        // Many files might not be encrypted, especially in debug builds
        if (!ignore) {
            g_logger.warning(stdext::format("unable to decrypt file (continuing anyway): %s", fullPath));
        }
#else
        if(!ignore)
            g_logger.fatal(stdext::format("unable to decrypt file: %s", fullPath));
#endif
    }

    return buffer;
}

bool ResourceManager::isFileEncryptedOrCompressed(const std::string& fileName)
{
    std::string fullPath = resolvePath(fileName);
    std::string fileContent;

    if (fullPath.find("/downloads") != std::string::npos) {
        auto dfile = g_http.getFile(fullPath.substr(10));
        if (dfile) {
            if (dfile->response.size() < 10)
                return false;
            fileContent = std::string(dfile->response.begin(), dfile->response.begin() + 10);
        }
    }

    if (fileContent.empty()) {
        PHYSFS_File* file = PHYSFS_openRead(fullPath.c_str());
        if (!file)
            stdext::throw_exception(stdext::format("unable to open file '%s': %s", fullPath, PHYSFS_getErrorByCode(PHYSFS_getLastErrorCode())));

        int fileSize = std::min<int>(10, PHYSFS_fileLength(file));
        fileContent.resize(fileSize);
        PHYSFS_readBytes(file, (void*)&fileContent[0], fileSize);
        PHYSFS_close(file);
    }

    if (fileContent.size() < 10)
        return false;
    
    if (fileContent.substr(0, 4).compare("ENC3") == 0)
        return true;

#ifdef DEF_DEFINITION
    // Check for ENCX format when DEF_DEFINITION is active
    if (fileContent.substr(0, 4).compare("ENCX") == 0)
        return true;
#endif

    if ((uint8_t)fileContent[0] != 0x1f || (uint8_t)fileContent[1] != 0x8b || (uint8_t)fileContent[2] != 0x08) {
        return false;
    }

    return true;
}

bool ResourceManager::writeFileBuffer(const std::string& fileName, const uchar* data, uint size)
{
    // Verify write directory is set up
    const char* writeDir = PHYSFS_getWriteDir();
    if (!writeDir) {
        g_logger.error(stdext::format("No write directory set when trying to write '%s'", fileName));
        // Try to set up write directory again
        if (!setupWriteDir("OTClientV8", g_app.getCompactName().empty() ? "otclientv8" : g_app.getCompactName())) {
            g_logger.error("Failed to setup write directory for config save");
            return false;
        }
        writeDir = PHYSFS_getWriteDir();
        if (!writeDir) {
            g_logger.error("Still no write directory after setup attempt");
            return false;
        }
    }
    
    //g_logger.info(stdext::format("Writing file '%s' to write dir: %s", fileName, writeDir));
    
    PHYSFS_file* file = PHYSFS_openWrite(fileName.c_str());
    if(!file) {
        g_logger.error(stdext::format("unable to open file for writing '%s': %s", fileName, PHYSFS_getErrorByCode(PHYSFS_getLastErrorCode())));
        g_logger.error(stdext::format("Current write dir: %s", writeDir ? writeDir : "NULL"));
        
        // List contents of write directory for debugging
        auto files = listDirectoryFiles("", false, true);
        //g_logger.info(stdext::format("Files in write directory (%d total):", files.size()));
        for (const auto& f : files) {
            //g_logger.info(stdext::format("  - %s", f));
        }
        
        return false;
    }

    PHYSFS_sint64 bytesWritten = PHYSFS_writeBytes(file, (void*)data, size);
    PHYSFS_close(file);
    
    if (bytesWritten != size) {
        g_logger.error(stdext::format("Failed to write complete file '%s': wrote %lld of %u bytes", fileName, bytesWritten, size));
        return false;
    }
    
    //g_logger.info(stdext::format("Successfully wrote file '%s' (%u bytes)", fileName, size));
    return true;
}

bool ResourceManager::writeFileStream(const std::string& fileName, std::iostream& in)
{
    std::streampos oldPos = in.tellg();
    in.seekg(0, std::ios::end);
    std::streampos size = in.tellg();
    in.seekg(0, std::ios::beg);
    std::vector<char> buffer(size);
    in.read(&buffer[0], size);
    bool ret = writeFileBuffer(fileName, (const uchar*)&buffer[0], size);
    in.seekg(oldPos, std::ios::beg);
    return ret;
}

bool ResourceManager::writeFileContents(const std::string& fileName, const std::string& data)
{
    return writeFileBuffer(fileName, (const uchar*)data.c_str(), data.size());
}

FileStreamPtr ResourceManager::openFile(const std::string& fileName, bool dontCache)
{
    std::string fullPath = resolvePath(fileName);
    if (isFileEncryptedOrCompressed(fullPath) || !dontCache) {
        return FileStreamPtr(new FileStream(fullPath, readFileContents(fullPath)));
    }
    PHYSFS_File* file = PHYSFS_openRead(fullPath.c_str());
    if (!file)
        stdext::throw_exception(stdext::format("unable to open file '%s': %s", fullPath, PHYSFS_getErrorByCode(PHYSFS_getLastErrorCode())));
    return FileStreamPtr(new FileStream(fullPath, file, false));
}

FileStreamPtr ResourceManager::appendFile(const std::string& fileName)
{
    PHYSFS_File* file = PHYSFS_openAppend(fileName.c_str());
    if(!file)
        stdext::throw_exception(stdext::format("failed to append file '%s': %s", fileName, PHYSFS_getErrorByCode(PHYSFS_getLastErrorCode())));
    return FileStreamPtr(new FileStream(fileName, file, true));
}

FileStreamPtr ResourceManager::createFile(const std::string& fileName)
{
    PHYSFS_File* file = PHYSFS_openWrite(fileName.c_str());
    if(!file)
        stdext::throw_exception(stdext::format("failed to create file '%s': %s", fileName, PHYSFS_getErrorByCode(PHYSFS_getLastErrorCode())));
    return FileStreamPtr(new FileStream(fileName, file, true));
}

bool ResourceManager::deleteFile(const std::string& fileName)
{
    return PHYSFS_delete(resolvePath(fileName).c_str()) != 0;
}

bool ResourceManager::makeDir(const std::string directory)
{
    return PHYSFS_mkdir(directory.c_str());
}

std::list<std::string> ResourceManager::listDirectoryFiles(const std::string& directoryPath, bool fullPath /* = false */, bool raw /*= false*/)
{
    std::list<std::string> files;
    auto path = raw ? directoryPath : resolvePath(directoryPath);
    auto rc = PHYSFS_enumerateFiles(path.c_str());

    if (!rc)
        return files;

    for (int i = 0; rc[i] != NULL; i++) {
        if(fullPath)
            files.push_back(path + "/" + rc[i]);
        else
            files.push_back(rc[i]);
    }

    PHYSFS_freeList(rc);
    files.sort();
    return files;
}

std::string ResourceManager::resolvePath(std::string path)
{
    if(!stdext::starts_with(path, "/")) {
        std::string scriptPath = "/" + g_lua.getCurrentSourcePath();
        if(!scriptPath.empty())
            path = scriptPath + "/" + path;
        else
            g_logger.traceWarning(stdext::format("the following file path is not fully resolved: %s", path));
    }
    stdext::replace_all(path, "//", "/");
    
#ifdef DEF_DEFINITION
    // Debug log for ENCX system with special focus on PNG files
    if (path.find(".png") != std::string::npos) {
        ////g_logger.info(stdext::format("[ENCX-DEBUG] PNG resolvePath: Looking for '%s'", path));
    } else {
        ////g_logger.info(stdext::format("ENCX resolvePath: Looking for '%s'", path));
    }
#endif
	
	// If the path has no extension, treat it as a PNG and try .png and .png.enc
	{
		size_t lastSlash = path.find_last_of('/');
		size_t lastDot = path.find_last_of('.');
		bool hasExtension = (lastDot != std::string::npos) && (lastSlash == std::string::npos || lastDot > lastSlash);
		if (!hasExtension) {
			static const std::string layouts_prefix_png = "/layouts/";
			static const std::string extra_check_png[] = { "/mods", "/data", "/modules" };
			
			std::string pngPath = path + ".png";
			if (PHYSFS_exists(pngPath.c_str())) {
				return pngPath;
			}
			if (!m_layout.empty()) {
				std::string layoutPng = layouts_prefix_png + m_layout + pngPath;
				if (PHYSFS_exists(layoutPng.c_str())) {
					return layoutPng;
				}
			}
			for (auto extra : extra_check_png) {
				std::string extraPng = extra + pngPath;
				if (PHYSFS_exists(extraPng.c_str())) {
					return extraPng;
				}
			}
			
			std::string pngEncPath = pngPath + ".enc";
			if (PHYSFS_exists(pngEncPath.c_str())) {
				return pngEncPath;
			}
			if (!m_layout.empty()) {
				std::string layoutPngEnc = layouts_prefix_png + m_layout + pngEncPath;
				if (PHYSFS_exists(layoutPngEnc.c_str())) {
					return layoutPngEnc;
				}
			}
			for (auto extra : extra_check_png) {
				std::string extraPngEnc = extra + pngEncPath;
				if (PHYSFS_exists(extraPngEnc.c_str())) {
					return extraPngEnc;
				}
			}
		}
	}
    
    // Original path exists - return it
    if(PHYSFS_exists(path.c_str())) {
#ifdef DEF_DEFINITION
        if (path.find(".png") != std::string::npos) {
            ////g_logger.info(stdext::format("[ENCX-DEBUG] PNG resolvePath: Found original file '%s'", path));
        } else {
            ////g_logger.info(stdext::format("ENCX resolvePath: Found original file '%s'", path));
        }
#endif
        return path;
    }
    
    // Try layout and extra paths for original file first
    static const std::string layouts_prefix = "/layouts/";
    if (!m_layout.empty()) {
        if (PHYSFS_exists((layouts_prefix + m_layout + path).c_str())) {
            return layouts_prefix + m_layout + path;
        }
    }
    
    static const std::string extra_check[] = { "/mods", "/data", "/modules" };
    for (auto extra : extra_check) {
        if (PHYSFS_exists((extra + path).c_str())) {
            return extra + path;
        }
    }
    
#ifdef DEF_DEFINITION
    // When DEF_DEFINITION is active, try .enc versions as fallback
    std::string encPath = path + ".enc";
    if (path.find(".png") != std::string::npos) {
        ////g_logger.info(stdext::format("[ENCX-DEBUG] PNG resolvePath: Trying .enc version '%s'", encPath));
    } else {
        ////g_logger.info(stdext::format("ENCX resolvePath: Trying .enc version '%s'", encPath));
    }
    
    if(PHYSFS_exists(encPath.c_str())) {
        if (path.find(".png") != std::string::npos) {
            ////g_logger.info(stdext::format("[ENCX-DEBUG] PNG resolvePath: Found .enc file '%s'", encPath));
        } else {
            ////g_logger.info(stdext::format("ENCX resolvePath: Found .enc file '%s'", encPath));
        }
        return encPath;
    }
    
    // Try .enc version in layout
    if (!m_layout.empty()) {
        if (PHYSFS_exists((layouts_prefix + m_layout + path + ".enc").c_str())) {
            return layouts_prefix + m_layout + path + ".enc";
        }
    }
    
    // Try .enc version in extra paths
    for (auto extra : extra_check) {
        std::string extraEncPath = extra + path + ".enc";
        if (path.find(".png") != std::string::npos) {
            //////g_logger.info(stdext::format("[ENCX-DEBUG] PNG resolvePath: Trying extra .enc '%s'", extraEncPath));
        } else {
            ////g_logger.info(stdext::format("ENCX resolvePath: Trying extra .enc '%s'", extraEncPath));
        }
        
        if (PHYSFS_exists(extraEncPath.c_str())) {
            if (path.find(".png") != std::string::npos) {
                ////g_logger.info(stdext::format("[ENCX-DEBUG] PNG resolvePath: Found extra .enc '%s'", extraEncPath));
            } else {
                ////g_logger.info(stdext::format("ENCX resolvePath: Found extra .enc '%s'", extraEncPath));
            }
            return extraEncPath;
        }
    }
    
    if (path.find(".png") != std::string::npos) {
        ////g_logger.info(stdext::format("[ENCX-DEBUG] PNG resolvePath: No .enc version found, returning original '%s'", path));
    } else {
        ////g_logger.info(stdext::format("ENCX resolvePath: No .enc version found, returning original '%s'", path));
    }
#endif
    
    return path;
}
std::string ResourceManager::guessFilePath(const std::string& filename, const std::string& type)
{
    if(isFileType(filename, type))
        return filename;
    return filename + "." + type;
}

bool ResourceManager::isFileType(const std::string& filename, const std::string& type)
{
    if(stdext::ends_with(filename, std::string(".") + type))
        return true;
    
    // Check for encrypted version
    if(stdext::ends_with(filename, std::string(".") + type + ".enc"))
        return true;
    
    return false;
}

std::string ResourceManager::fileChecksum(const std::string& path) {
    static std::map<std::string, std::string> cache;

    auto it = cache.find(path);
    if (it != cache.end())
        return it->second;

    PHYSFS_File* file = PHYSFS_openRead(path.c_str());
    if(!file)
        return "";

    int fileSize = PHYSFS_fileLength(file);
    std::string buffer(fileSize, 0);
    PHYSFS_readBytes(file, (void*)&buffer[0], fileSize);
    PHYSFS_close(file);

    auto checksum = g_crypt.crc32(buffer, false);
    cache[path] = checksum;

    return checksum;
}

std::map<std::string, std::string> ResourceManager::filesChecksums()
{
    std::map<std::string, std::string> ret;
#ifndef __EMSCRIPTEN__
    if (!m_memoryData)
        return ret;

    zip_source_t* src;
    zip_t* za;
    zip_stat_t file_stat;
    zip_error_t error;
    zip_error_init(&error);
    zip_stat_init(&file_stat);

    if ((src = zip_source_buffer_create(m_memoryData->data(), m_memoryData->size(), 0, &error)) == NULL)
        g_logger.fatal(stdext::format("can't create source: %s", zip_error_strerror(&error)));

    if ((za = zip_open_from_source(src, ZIP_RDONLY, &error)) == NULL)
        g_logger.fatal(stdext::format("can't open zip from source: %s", zip_error_strerror(&error)));

    zip_int64_t entries = zip_get_num_entries(za, 0);
    for (zip_int64_t entry_idx = 0; entry_idx < entries; entry_idx++) {
        if (zip_stat_index(za, entry_idx, 0, &file_stat)) {
            g_logger.fatal(stdext::format("error stat-ing file at index %i: %s",
                    (int)(entry_idx), zip_strerror(za)));
        }
        if (!(file_stat.valid & ZIP_STAT_NAME)) {
            g_logger.warning(stdext::format("warning: skipping entry at index %i with invalid name.",
                    (int)entry_idx));
            continue;
        }
        std::string name(file_stat.name);
        if (name.empty()) continue;
        if (name[0] != '/')
            name = std::string("/") + name;
        if (name.back() == '/' || file_stat.size == 0) // dir
            continue;
        stdext::replace_all(name, "\\", "/");
        ret[name] = stdext::dec_to_hex(file_stat.crc);
    }

    if (zip_close(za) < 0)
        g_logger.fatal(stdext::format("can't close zip archive: %s", zip_strerror(za)));
    zip_error_fini(&error);
#endif
    return ret;
}

std::string ResourceManager::selfChecksum() {
#ifdef ANDROID
    return "";
#else
    static std::string checksum;
    if (!checksum.empty())
        return checksum;

    std::ifstream file(m_binaryPath.string(), std::ios::binary);
    if (!file.is_open())
        return "";

    std::string buffer(std::istreambuf_iterator<char>(file), {});
    file.close();

    checksum = g_crypt.crc32(buffer, false);
    return checksum;
#endif
}

void ResourceManager::updateData(const std::set<std::string>& files, bool reMount) {
#if not(defined(__EMSCRIPTEN__) || defined(FREE_VERSION))
    if (!m_loadedFromArchive)
        g_logger.fatal("Client can be updated only when running from zip archive");

    ////g_logger.info(stdext::format("Updating client, %i files", files.size()));

    zip_source_t *src;
    zip_t *za;
    zip_error_t error;
    zip_error_init(&error);

    if ((src = zip_source_buffer_create(0, 0, 0, &error)) == NULL)
        return g_logger.fatal(stdext::format("can't create source: %s", zip_error_strerror(&error)));
    zip_source_keep(src);

    if ((za = zip_open_from_source(src, ZIP_TRUNCATE, &error)) == NULL)
        return g_logger.fatal(stdext::format("can't open zip from source: %s", zip_error_strerror(&error)));

    zip_error_fini(&error);

    for (auto fileName : files) {
        if (fileName.empty())
            continue;
        if (fileName.size() > 1 && fileName[0] == '/')
            fileName = fileName.substr(1);
        zip_source_t* s;
        auto dFile = g_http.getFile(fileName);
        if (dFile) {
            if ((s = zip_source_buffer(za, dFile->response.data(), dFile->response.size(), 0)) == NULL)
                return g_logger.fatal(stdext::format("can't create source buffer: %s", zip_strerror(za)));
        } else {
            PHYSFS_File* file = PHYSFS_openRead((std::string("/") + fileName).c_str());
            if (!file)
                g_logger.fatal(stdext::format("unable to open file '%s': %s", fileName, PHYSFS_getErrorByCode(PHYSFS_getLastErrorCode())));

            int fileSize = PHYSFS_fileLength(file);
            void* buffer = malloc(fileSize);
            PHYSFS_readBytes(file, buffer, fileSize);
            PHYSFS_close(file);
            if ((s = zip_source_buffer(za, buffer, fileSize, 1)) == NULL)
                return g_logger.fatal(stdext::format("can't create source buffer: %s", zip_strerror(za)));
        }

        int fileIndex = zip_file_add(za, fileName.c_str(), s, ZIP_FL_OVERWRITE);
        if(fileIndex < 0)
            return g_logger.fatal(stdext::format("can't add file %s to zip archive: %s", fileName, zip_strerror(za)));
        if (zip_set_file_compression(za, fileIndex, ZIP_CM_DEFLATE, 1) != 0)
            return g_logger.fatal("Can't set file compression level");
    }

    if (zip_close(za) < 0)
        return g_logger.fatal(stdext::format("can't close zip archive: %s", zip_strerror(za)));

    zip_stat_t zst;
    if (zip_source_stat(src, &zst) < 0)
        return g_logger.fatal(stdext::format("can't stat source: %s", zip_error_strerror(zip_source_error(src))));
    
    size_t zipSize = zst.size;    

    if (zip_source_open(src) < 0)
        return g_logger.fatal(stdext::format("can't open source: %s", zip_error_strerror(zip_source_error(src))));

    PHYSFS_file* file = PHYSFS_openWrite("data.zip");
    if (!file)
        return g_logger.fatal(stdext::format("can't open data.zip for writing: %s", PHYSFS_getErrorByCode(PHYSFS_getLastErrorCode())));

    static const size_t CHUNK_SIZE = 1024 * 1024;
    std::vector<char> chunk(CHUNK_SIZE);
    while (zipSize > 0) {
        size_t currentChunk = std::min<size_t>(zipSize, CHUNK_SIZE);
        if ((zip_uint64_t)zip_source_read(src, chunk.data(), currentChunk) < currentChunk)
            return g_logger.fatal(stdext::format("can't read data from source: %s", zip_error_strerror(zip_source_error(src))));
        PHYSFS_writeBytes(file, chunk.data(), currentChunk);
        zipSize -= currentChunk;
    }

    PHYSFS_close(file);
    zip_source_close(src);
    zip_source_free(src);

    if (reMount) {
        unmountMemoryData();
        file = PHYSFS_openRead("data.zip");
        if (!file)
            g_logger.fatal(stdext::format("Can't open new data.zip"));

        int size = PHYSFS_fileLength(file);
        if (size < 1024)
            g_logger.fatal(stdext::format("New data.zip is invalid"));

        auto data = std::make_shared<std::vector<uint8_t>>(size);
        PHYSFS_readBytes(file, data->data(), data->size());
        PHYSFS_close(file);
        if (!mountMemoryData(data)) {
            g_logger.fatal("Error while mounting new data.zip");
        }
    }
#else
    g_logger.fatal("updateData is unsupported");
#endif
}

void ResourceManager::updateExecutable(std::string fileName)
{
#if defined(ANDROID) || defined(FREE_VERSION)
    g_logger.fatal("Executable cannot be updated on android or in free version");
#else
    if (fileName.size() <= 2) {
        g_logger.fatal("Invalid executable name");
    }

    if (fileName[0] == '/')
        fileName = fileName.substr(1);

    auto dFile = g_http.getFile(fileName);
    if (!dFile)
        g_logger.fatal(stdext::format("Cannot find executable: %s in downloads", fileName));

    std::filesystem::path path(m_binaryPath);
    auto newBinary = path.stem().string() + "-" + std::to_string(time(nullptr)) + path.extension().string();
    ////g_logger.info(stdext::format("Updating binary file: %s", newBinary));
    PHYSFS_file* file = PHYSFS_openWrite(newBinary.c_str());
    if (!file)
        return g_logger.fatal(stdext::format("can't open %s for writing: %s", newBinary, PHYSFS_getErrorByCode(PHYSFS_getLastErrorCode())));
    PHYSFS_writeBytes(file, dFile->response.data(), dFile->response.size());
    PHYSFS_close(file);

    std::filesystem::path newBinaryPath(std::filesystem::u8path(PHYSFS_getWriteDir()));
#if defined(WIN32) && not(defined(FREE_VERSION))
    installDlls(newBinaryPath);
#endif
#endif
}

std::string ResourceManager::createArchive(const std::map<std::string, std::string>& files)
{
#ifdef __EMSCRIPTEN__
    return "";
#else
    if (files.empty()) return "";

    zip_source_t* src;
    zip_t* za;
    zip_error_t error;
    zip_error_init(&error);

    if ((src = zip_source_buffer_create(0, 0, 0, &error)) == NULL)
        stdext::throw_exception(stdext::format("can't create source: %s", zip_error_strerror(&error)));
    zip_source_keep(src);

    if ((za = zip_open_from_source(src, ZIP_TRUNCATE, &error)) == NULL)
        stdext::throw_exception(stdext::format("can't open zip from source: %s", zip_error_strerror(&error)));

    zip_error_fini(&error);

    for (auto& file : files) {
        if (file.first.empty() || file.second.empty())
            continue;

        zip_source_t* s;
        if ((s = zip_source_buffer(za, file.second.data(), file.second.size(), 0)) == NULL)
            stdext::throw_exception(stdext::format("can't create source buffer: %s", zip_strerror(za)));

        std::string fileName = file.first;
        if (fileName.size() > 1 && fileName[0] == '/')
            fileName = fileName.substr(1);

        int fileIndex = zip_file_add(za, fileName.c_str(), s, ZIP_FL_OVERWRITE);
        if (fileIndex < 0)
            stdext::throw_exception(stdext::format("can't add file %s to zip archive: %s", fileName, zip_strerror(za)));
//        if (zip_set_file_compression(za, fileIndex, ZIP_CM_DEFLATE, 1) != 0)
//            stdext::throw_exception("Can't set file compression level");
    }

    if (zip_close(za) < 0)
        stdext::throw_exception(stdext::format("can't close zip archive: %s", zip_strerror(za)));

    zip_stat_t zst;
    if (zip_source_stat(src, &zst) < 0)
        stdext::throw_exception(stdext::format("can't stat source: %s", zip_error_strerror(zip_source_error(src))));

    size_t zipSize = zst.size;

    if (zip_source_open(src) < 0)
        stdext::throw_exception(stdext::format("can't open source: %s", zip_error_strerror(zip_source_error(src))));

    std::string data(zipSize, '\0');
    if ((zip_uint64_t)zip_source_read(src, data.data(), data.size()) != data.size())
        stdext::throw_exception(stdext::format("can't read data from source: %s", zip_error_strerror(zip_source_error(src))));

    zip_source_close(src);
    zip_source_free(src);

    return data;
#endif
}

std::map<std::string, std::string> ResourceManager::decompressArchive(std::string dataOrPath)
{
    std::map<std::string, std::string> ret;
#ifdef __EMSCRIPTEN__
    return ret;
#else
    if (dataOrPath.size() < 64) {
        dataOrPath = readFileContents(dataOrPath);
    }

    zip_source_t* src;
    zip_t* za;
    zip_stat_t file_stat;
    zip_error_t error;
    zip_error_init(&error);
    zip_stat_init(&file_stat);

    if ((src = zip_source_buffer_create(dataOrPath.c_str(), dataOrPath.size(), 0, &error)) == NULL)
        stdext::throw_exception(stdext::format("unpackArchive: can't create source: %s", zip_error_strerror(&error)));

    if ((za = zip_open_from_source(src, ZIP_RDONLY, &error)) == NULL)
        stdext::throw_exception(stdext::format("unpackArchive: can't open zip from source: %s", zip_error_strerror(&error)));

    zip_int64_t entries = zip_get_num_entries(za, 0);
    for (zip_int64_t entry_idx = 0; entry_idx < entries; entry_idx++) {
        if (zip_stat_index(za, entry_idx, 0, &file_stat)) {
            stdext::throw_exception(stdext::format("unpackArchive: error stat-ing file at index %i: %s",
                                          (int)(entry_idx), zip_strerror(za)));
        }
        if (!(file_stat.valid & ZIP_STAT_NAME)) {
            g_logger.warning(stdext::format("warning: skipping entry at index %i with invalid name.",
                                            (int)entry_idx));
            continue;
        }
        std::string name(file_stat.name);
        if (name.empty()) continue;
        if (name[0] != '/')
            name = std::string("/") + name;
        if (name.back() == '/' || file_stat.size == 0) // dir
            continue;
        stdext::replace_all(name, "\\", "/");

        zip_file_t* file = zip_fopen_index(za, entry_idx, 0);
        if(!file)
            stdext::throw_exception(stdext::format("can't open file from zip archive: %s - %s", name, zip_strerror(za)));
        std::string buffer(file_stat.size, '\0');
        zip_fread(file, buffer.data(), buffer.size());
        zip_fclose(file);
        ret[name] = std::move(buffer);
    }

    if (zip_close(za) < 0)
        stdext::throw_exception(stdext::format("can't close zip archive: %s", zip_strerror(za)));
    zip_error_fini(&error);
    return ret; // success
#endif
}

#if defined(WIN32) && not(defined(FREE_VERSION))
void ResourceManager::installDlls(std::filesystem::path dest)
{
    static std::list<std::string> dlls = {
        {"libEGL.dll"},
        {"libGLESv2.dll"},
        {"d3dcompiler_46.dll"},
        {"d3dcompiler_47.dll"}
    };

    int added_dlls = 0;
    for (auto& dll : dlls) {
        auto dll_path = m_binaryPath.parent_path();
        dll_path /= dll;
        if (!std::filesystem::exists(dll_path)) {
            continue;
        }
        auto out_path = dest;
        out_path /= dll;
        if (std::filesystem::exists(out_path)) {
            continue;
        }
        std::filesystem::copy_file(dll_path, out_path);
    }
}
#endif

#if defined(WITH_ENCRYPTION) && !defined(ANDROID)
void ResourceManager::encrypt(const std::string& seed) {
    const std::string dirsToCheck[] = { "data", "modules", "mods", "layouts" };
    const std::string luaExtension = ".lua";

    g_logger.setLogFile("encryption.log");
    ////g_logger.info("----------------------");

    std::queue<std::filesystem::path> toEncrypt;
    // you can add custom files here
    toEncrypt.push(std::filesystem::path(INIT_FILENAME));

    for (auto& dir : dirsToCheck) {
        if (!std::filesystem::exists(dir))
            continue;
        for(auto&& entry : std::filesystem::recursive_directory_iterator(std::filesystem::path(dir))) {
            if (!std::filesystem::is_regular_file(entry.path()))
                continue;
            std::string str(entry.path().string());
            // skip encryption for bot configs
            if (str.find("game_bot") != std::string::npos && str.find("default_config") != std::string::npos) {
                continue;
            }
            toEncrypt.push(entry.path());
        }
    }

    bool encryptForAndroid = seed.find("android") != std::string::npos;
    uint32_t uintseed = seed.empty() ? 0 : stdext::adler32((const uint8_t*)seed.c_str(), seed.size());

    while (!toEncrypt.empty()) {
        auto it = toEncrypt.front();
        toEncrypt.pop();
        std::ifstream in_file(it, std::ios::binary);
        if (!in_file.is_open())
            continue;
        std::string buffer(std::istreambuf_iterator<char>(in_file), {});
        in_file.close();
        if (buffer.size() >= 4 && buffer.substr(0, 4).compare("ENC3") == 0)
            continue; // already encrypted

        if (!encryptForAndroid && it.extension().string() == luaExtension && it.filename().string() != INIT_FILENAME) {
            std::string bytecode = g_lua.generateByteCode(buffer, it.string());
            if (bytecode.length() > 10) {
                buffer = bytecode;
                ////g_logger.info(stdext::format("%s - lua bytecode encrypted", it.string()));
            } else {
                ////g_logger.info(stdext::format("%s - lua but not bytecode encrypted", it.string()));
            }
        }

        if (!encryptBuffer(buffer, uintseed)) { // already encrypted
            ////g_logger.info(stdext::format("%s - already encrypted", it.string()));
            continue;
        }

        std::ofstream out_file(it, std::ios::binary);
        if (!out_file.is_open())
            continue;
        out_file.write(buffer.data(), buffer.size());
        out_file.close();
        ////g_logger.info(stdext::format("%s - encrypted", it.string()));
    }
}
#endif 

bool ResourceManager::decryptBuffer(std::string& buffer) {
#ifdef FREE_VERSION
    return false;
#else
    if (buffer.size() < 5)
        return true;

    if (buffer.substr(0, 4).compare("ENC3") != 0) {
        return false;
    }

    uint64_t key = *(uint64_t*)&buffer[4];
    uint32_t compressed_size = *(uint32_t*)&buffer[12];
    uint32_t size = *(uint32_t*)&buffer[16];
    uint32_t adler = *(uint32_t*)&buffer[20];

    if (compressed_size < buffer.size() - 24)
        return false;

    g_crypt.bdecrypt((uint8_t*)&buffer[24], compressed_size, key);
    std::string new_buffer;
    new_buffer.resize(size);
    unsigned long new_buffer_size = new_buffer.size();
    if (uncompress((uint8_t*)new_buffer.data(), &new_buffer_size, (uint8_t*)&buffer[24], compressed_size) != Z_OK)
        return false;

    uint32_t addlerCheck = stdext::adler32((const uint8_t*)&new_buffer[0], size);
    if (adler != addlerCheck) {
        uint32_t cseed = adler ^ addlerCheck;
        if (m_customEncryption == 0) {
            m_customEncryption = cseed;
        }
        if ((addlerCheck ^ m_customEncryption) != adler) {
            return false;
        }
    }

    buffer = new_buffer;
    return true;
#endif
}

#ifdef WITH_ENCRYPTION
bool ResourceManager::encryptBuffer(std::string& buffer, uint32_t seed) {
    if (buffer.size() >= 4 && buffer.substr(0, 4).compare("ENC3") == 0)
        return false; // already encrypted

    // not random beacause it would require to update to new files each time
    int64_t key = stdext::adler32((const uint8_t*)&buffer[0], buffer.size());
    key <<= 32;
    key += stdext::adler32((const uint8_t*)&buffer[0], buffer.size() / 2);

    std::string new_buffer(24 + buffer.size() * 2, '0');
    new_buffer[0] = 'E';
    new_buffer[1] = 'N';
    new_buffer[2] = 'C';
    new_buffer[3] = '3';

    unsigned long dstLen = new_buffer.size() - 24;
    if (compress((uint8_t*)&new_buffer[24], &dstLen, (const uint8_t*)buffer.data(), buffer.size()) != Z_OK) {
        g_logger.error("Error while compressing");
        return false;
    }
    new_buffer.resize(24 + dstLen);

    *(int64_t*)&new_buffer[4] = key;
    *(uint32_t*)&new_buffer[12] = (uint32_t)dstLen;
    *(uint32_t*)&new_buffer[16] = (uint32_t)buffer.size();
    *(uint32_t*)&new_buffer[20] = ((uint32_t)stdext::adler32((const uint8_t*)&buffer[0], buffer.size())) ^ seed;

    g_crypt.bencrypt((uint8_t*)&new_buffer[0] + 24, new_buffer.size() - 24, key);
    buffer = new_buffer;
    return true;
}
#endif

// ENCX System Implementation
bool ResourceManager::encryptBufferX(std::string& buffer, uint32_t seed) {
    if (buffer.size() >= 4 && buffer.substr(0, 4).compare("ENCX") == 0)
        return false; // already encrypted

    // Generate deterministic key based on content and fixed base
    uint32_t contentHash = stdext::adler32((const uint8_t*)buffer.data(), buffer.size());
    uint64_t key = (0xA5F1C3E7ULL ^ seed) ^ contentHash;

    // Create new buffer with ENCX header
    std::string new_buffer(20 + buffer.size() * 2, '0');
    new_buffer[0] = 'E';
    new_buffer[1] = 'N';
    new_buffer[2] = 'C';
    new_buffer[3] = 'X';

    // Compress the original data
    unsigned long compressedSize = new_buffer.size() - 20;
    if (compress((uint8_t*)&new_buffer[20], &compressedSize, (const uint8_t*)buffer.data(), buffer.size()) != Z_OK) {
        g_logger.error("ENCX: Error while compressing");
        return false;
    }
    new_buffer.resize(20 + compressedSize);

    // Store metadata
    *(uint64_t*)&new_buffer[4] = key;                    // 8 bytes: encryption key
    *(uint32_t*)&new_buffer[12] = (uint32_t)compressedSize; // 4 bytes: compressed size
    *(uint32_t*)&new_buffer[16] = (uint32_t)buffer.size();   // 4 bytes: original size

    // Encrypt the compressed data
#ifdef WITH_ENCRYPTION
    g_crypt.bencrypt((uint8_t*)&new_buffer[20], compressedSize, key);
#else
    // Fallback encryption for builds without WITH_ENCRYPTION (like Android)
    g_crypt.bdecrypt((uint8_t*)&new_buffer[20], compressedSize, key);
#endif
    
    buffer = new_buffer;
    return true;
}

bool ResourceManager::decryptBufferX(std::string& buffer) {
    if (buffer.size() < 20)
        return false;

    if (buffer.substr(0, 4).compare("ENCX") != 0) {
        return false;
    }

    uint64_t key = *(uint64_t*)&buffer[4];
    uint32_t compressedSize = *(uint32_t*)&buffer[12];
    uint32_t originalSize = *(uint32_t*)&buffer[16];

    if (compressedSize > buffer.size() - 20)
        return false;

    // Decrypt the compressed data
    g_crypt.bdecrypt((uint8_t*)&buffer[20], compressedSize, key);
    
    // Decompress
    std::string new_buffer;
    new_buffer.resize(originalSize);
    unsigned long new_buffer_size = new_buffer.size();
    if (uncompress((uint8_t*)new_buffer.data(), &new_buffer_size, (uint8_t*)&buffer[20], compressedSize) != Z_OK)
        return false;

    buffer = new_buffer;
    return true;
}

std::string ResourceManager::readSprParts(const std::string& dir) {
    std::string result;
    int partNum = 1;
    
    while (true) {
        std::string partPath = stdext::format("%s/part_%d.spr.enc", dir, partNum);
        
        if (!fileExists(partPath)) {
            if (partNum == 1) {
                g_logger.fatal(stdext::format("No sprite parts found in directory: %s", dir));
            }
            break;
        }
        
        std::string partContent = readFileContents(partPath);
        if (!decryptBufferX(partContent)) {
            g_logger.fatal(stdext::format("Failed to decrypt sprite part: %s", partPath));
        }
        
        result += partContent;
        partNum++;
    }
    
    return result;
}

void ResourceManager::setLayout(std::string layout)
{
    stdext::tolower(layout);
    stdext::replace_all(layout, "/", "");
    if (layout == "default") {
        layout = "";
    }
    if (!layout.empty() && !PHYSFS_exists((std::string("/layouts/") + layout).c_str())) {
        g_logger.error(stdext::format("Layour %s doesn't exist, using default", layout));
        return;
    }
    m_layout = layout;
}

bool ResourceManager::mountMemoryData(const std::shared_ptr<std::vector<uint8_t>>& data)
{
    //g_logger.info("ResourceManager::mountMemoryData() - Starting");
    
    if (!data || data->size() < 1024) {
        g_logger.error("ResourceManager::mountMemoryData() - Invalid data or size < 1024");
        return false;
    }

    //g_logger.info(stdext::format("ResourceManager::mountMemoryData() - Mounting %d bytes", data->size()));
    
    if (PHYSFS_mountMemory(data->data(), data->size(), nullptr,
                           "memory_data.zip", "/", 0)) {
        //g_logger.info("ResourceManager::mountMemoryData() - Memory mount successful, checking for init.lua");
        
        bool hasInitFile = false;
        if (PHYSFS_exists(INIT_FILENAME.c_str())) {
            hasInitFile = true;
            //g_logger.info("ResourceManager::mountMemoryData() - init.lua found");
        }
        
#ifdef DEF_DEFINITION
        // If DEF_DEFINITION is active, also check for init.lua.enc
        if (!hasInitFile && PHYSFS_exists((INIT_FILENAME + ".enc").c_str())) {
            hasInitFile = true;
            //g_logger.info("ResourceManager::mountMemoryData() - init.lua.enc found (DEF_DEFINITION active)");
        }
#endif

        if (hasInitFile) {
            //g_logger.info("ResourceManager::mountMemoryData() - init file found, setup complete");
            m_loadedFromArchive = true;
            m_memoryData = data;
            return true;
        } else {
            g_logger.error("ResourceManager::mountMemoryData() - init.lua not found in mounted data");
        }
        PHYSFS_unmount("memory_data.zip");
    } else {
        g_logger.error(stdext::format("ResourceManager::mountMemoryData() - PHYSFS_mountMemory failed: %s", PHYSFS_getErrorByCode(PHYSFS_getLastErrorCode())));
    }
    return false;
}

void ResourceManager::unmountMemoryData()
{
    if (!m_memoryData)
        return;

    if (!PHYSFS_unmount("memory_data.zip")) {
        g_logger.fatal(stdext::format("Unable to unmount memory data", PHYSFS_getErrorByCode(PHYSFS_getLastErrorCode())));
    }
    m_memoryData = nullptr;
    m_loadedFromMemory = false;
    m_loadedFromArchive = false;
}

bool ResourceManager::testConfigSave()
{
    //g_logger.info("=== TESTING CONFIG SAVE FUNCTIONALITY ===");
    
    const char* writeDir = PHYSFS_getWriteDir();
    if (!writeDir) {
        g_logger.error("No write directory set - config save will fail");
        return false;
    }
    
    //g_logger.info(stdext::format("Write directory: %s", writeDir));
    
    // Test simple file write
    std::string testContent = "# Test config file\ntest_key: test_value\n";
    std::string testFile = "test_config.otml";
    
    if (!writeFileContents(testFile, testContent)) {
        g_logger.error("Failed to write test config file");
        return false;
    }
    
    //g_logger.info("Successfully wrote test config file");
    
    // Test reading it back
    if (!fileExists(testFile)) {
        g_logger.error("Test config file does not exist after writing");
        return false;
    }
    
    std::string readContent = readFileContents(testFile);
    if (readContent != testContent) {
        g_logger.error("Test config file content mismatch");
        g_logger.error(stdext::format("Expected: %s", testContent));
        g_logger.error(stdext::format("Got: %s", readContent));
        return false;
    }
    
    //g_logger.info("Successfully read back test config file with correct content");
    
    // Clean up test file
    deleteFile(testFile);
    
    //g_logger.info("=== CONFIG SAVE TEST PASSED ===");
    return true;
}

void ResourceManager::testConfigLoadSave()
{
    //g_logger.info("=== TESTING CONFIG PATH RESOLUTION ===");
    
    std::string configPath = "/config.otml";
    std::string resolvedWritePath = resolvePath(configPath);
    
    //g_logger.info(stdext::format("Original path: %s", configPath));
    //g_logger.info(stdext::format("Resolved path for reading: %s", resolvedWritePath));
    
    // Check if config file exists
    bool exists = fileExists(configPath);
    //g_logger.info(stdext::format("Config file exists: %s", exists ? "YES" : "NO"));
    
    if (exists) {
        try {
            std::string content = readFileContents(configPath, true); // safe read
            //g_logger.info(stdext::format("Config file size: %d bytes", content.size()));
            
            // Show first few lines for debugging
            std::istringstream iss(content);
            std::string line;
            int lineCount = 0;
            //g_logger.info("=== CONFIG FILE CONTENT (first 5 lines) ===");
            while (std::getline(iss, line) && lineCount < 5) {
                //g_logger.info(stdext::format("Line %d: %s", lineCount + 1, line));
                lineCount++;
            }
            //g_logger.info("=== END CONFIG CONTENT ===");
        } catch (const std::exception& e) {
            g_logger.error(stdext::format("Error reading config file: %s", e.what()));
        }
    }
    
    // Test write location
    const char* writeDir = PHYSFS_getWriteDir();
    if (writeDir) {
        //g_logger.info(stdext::format("Write directory: %s", writeDir));
        
        // List files in write directory
        auto files = listDirectoryFiles("", false, true);
        //g_logger.info(stdext::format("Files in write directory (%d total):", files.size()));
        for (const auto& f : files) {
            if (f.find("config") != std::string::npos || f.find(".otml") != std::string::npos) {
                //g_logger.info(stdext::format("  -> %s", f));
            }
        }
    }
    
    //g_logger.info("=== CONFIG PATH RESOLUTION TEST COMPLETE ===");
}
