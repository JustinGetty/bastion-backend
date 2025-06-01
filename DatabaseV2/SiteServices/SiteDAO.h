//
// Created by root on 6/1/25.
//

#ifndef SITEDAO_H
#define SITEDAO_H
#include "ISiteReader.h"
#include "ISiteWriter.h"
#include "sqlite3.h"



class SiteDAO : public ISiteReader, public ISiteWriter {
    sqlite3 *db;
    sqlite3_stmt *stmtInsertRequest;
    sqlite3_stmt *stmtGetSiteIdBySpaId;

public:
    explicit SiteDAO(sqlite3* db);
    ~SiteDAO() override;

    void insertRequest(const int site_id, const std::string username, const int approved) override;
    int getClientIdBySpaId(const std::string spa_id) override;
};



#endif //SITEDAO_H
