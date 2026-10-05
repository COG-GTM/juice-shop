process.env.NODE_ENV = 'test'
// deterministic salts so hardcoded continue codes in the API tests still decode
process.env.CONTINUE_CODE_SALT = 'this is my salt'
process.env.CONTINUE_CODE_FIND_IT_SALT = 'this is the salt for findIt challenges'
process.env.CONTINUE_CODE_FIX_IT_SALT = 'yet another salt for the fixIt challenges'
