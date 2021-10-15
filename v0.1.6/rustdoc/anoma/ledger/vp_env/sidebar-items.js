initSidebarItems({"enum":[["RuntimeError","These runtime errors will abort VP execution immediately"]],"fn":[["add_gas","Add a gas cost incured in a validity predicate"],["get_block_epoch","Getting the block epoch. The epoch is that of the block to which the current transaction is being applied."],["get_block_hash","Getting the block hash. The height is that of the block to which the current transaction is being applied."],["get_block_height","Getting the block height. The height is that of the block to which the current transaction is being applied."],["get_chain_id","Getting the chain ID."],["has_key_post","Storage `has_key` in posterior state (after tx execution). It will try to check the write log first and if no entry found then the storage."],["has_key_pre","Storage `has_key` in prior state (before tx execution). It will try to read from the storage."],["iter_post_next","Storage prefix iterator next for posterior state (after tx execution). It will try to read from the write log first and if no entry found then from the storage."],["iter_pre_next","Storage prefix iterator for prior state (before tx execution). It will try to read from the storage."],["iter_prefix","Storage prefix iterator. It will try to get an iterator from the storage."],["read_post","Storage read posterior state (after tx execution). It will try to read from the write log first and if no entry found then from the storage."],["read_pre","Storage read prior state (before tx execution). It will try to read from the storage."]],"type":[["Result","VP environment function result"]]});