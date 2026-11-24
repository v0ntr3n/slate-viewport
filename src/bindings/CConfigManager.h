#pragma once

#include "cocos2d.h"
#include "sqlite3.h"

#include <cstddef>
#include <map>
#include <string>
#include <vector>

class CTable {
public:
    CTable(sqlite3* db, const std::string& dbPath, const std::string& tableName,
           const std::string& dbFile = "");
    CTable(sqlite3* db, const std::string& dbPath, const std::string& dbAlias,
           const std::string& tableName, bool needAttach);
    virtual ~CTable();

    bool init();
    void finalizeStatements();
    bool rebind(sqlite3* db, const std::string& dbPath);
    void release() {}

    cocos2d::CCArray* getRowById(const std::string& id);
    cocos2d::CCArray* getColName();
    cocos2d::CCArray* getColumnName() { return getColName(); }
    cocos2d::CCArray* getIdsByConditionStr(const std::string& condition);

    const std::string& dbPath() const { return m_dbPath; }
    const std::string& dbFile() const { return m_dbFile; }
    const std::string& tableName() const { return m_tableName; }

    static std::string buildReadOnlyUri(const std::string& path);

private:
    sqlite3*      m_db = nullptr;
    sqlite3_stmt* m_stmtById = nullptr;
    std::string   m_dbPath;
    std::string   m_dbFile;
    std::string   m_tableName;
};

class CConfigurationManager {
public:
    // Bounded SQLite page cache limits (negative values specify KiB).
    static constexpr int kMainCacheSizeKiB = -2048;
    static constexpr int kAttachedCacheSizeKiB = -512;  // 512 KiB cap per opened DB

    static CConfigurationManager* sharedConfigurationManager(bool reload = false);

    CConfigurationManager();
    virtual ~CConfigurationManager();

    bool init();
    bool reload();
    CTable* getTable(const std::string& dbFile, const std::string& tableName);
    std::string getDbFile(const std::string& dbFile);
    std::size_t openDbCount() const { return m_dbs.size(); }

private:
    sqlite3* openOrGetDb(const std::string& normalizedPath);
    void closeAllDbs();

    std::map<std::string, sqlite3*> m_dbs;
    std::map<std::string, CTable*>  m_tables;
    std::vector<CTable*>            m_ownedTables;
};
