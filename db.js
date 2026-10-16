'use strict';

const { DatabaseSync } = require('node:sqlite');

class Database {
  constructor(file) {
    this.db = new DatabaseSync(file);
  }

  exec(sql) {
    return this.db.exec(sql);
  }

  prepare(sql) {
    return this.db.prepare(sql);
  }

  pragma(value) {
    return this.db.prepare('PRAGMA ' + value).get();
  }

  transaction(fn) {
    return (...args) => {
      this.db.exec('BEGIN');
      try {
        const result = fn(...args);
        this.db.exec('COMMIT');
        return result;
      } catch (error) {
        this.db.exec('ROLLBACK');
        throw error;
      }
    };
  }

  close() {
    return this.db.close();
  }
}

module.exports = Database;
