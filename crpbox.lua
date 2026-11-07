-- Copyright (c) 2026 PPiligrimm
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

local crypto = require( "plugin.sha" )

local lib = {}

lib.random = function(bytes)
  if not bytes then
    bytes = 32
  end
  
  local f = io.open("/dev/urandom", "rb")
  if f then
    local random = f:read(bytes)
    f:close()
    
    if random and #random == bytes then
      return random
    end
  end
  
  local cmd = string.format('powershell -Command "$r=[byte[]]::new(%d); (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($r); [System.Console]::OpenStandardOutput().Write($r, 0, $r.Length)"', bytes)
  local handle = io.popen(cmd, "rb")
  if handle then
    local random = handle:read(bytes)
    handle:close()
    
    if random and #random == bytes then
      return random
    end
  end
  
  error("Cannot get random")
end

lib.constime_compare = function(str1, str2)
    if type(str1) ~= "string" or type(str2) ~= "string" then
        local _ = (str1 == str2)
        return false
    end

    local len1 = #str1
    local len2 = #str2
    
    local errors = (len1 == len2) and 0 or 1
    
    for i = 1, len1 do
        local b1 = string.byte(str1, i)
        local b2 = string.byte(str2, i) or -1
        
        local match_error = (b1 == b2) and 0 or 1
        
        errors = errors + match_error
    end
    
    return errors == 0
end

local I_N_for_K_I = {
  ["1000"] = 1,
  ["2000"] = 2,
  ["4000"] = 3,
  ["8000"] = 4,
  ["16000"] = 5,
  ["32000"] = 6,
  ["64000"] = 7,
  ["128000"] = 8,
  ["256000"] = 9,
  ["512000"] = 10,
  ["1024000"] = 11,
  ["2048000"] = 12,
  ["4096000"] = 13,
  ["8192000"] = 14,
  ["16384000"] = 15,
  ["32768000"] = 16,
  ["65536000"] = 17,
}

lib.crp_file = function( inputpath, outputpath, key, mode, settings )
  key = string.format("%s",key)
  settings = settings or {}
  
  -- title
  local crypter_version = 3
  
  -- cryption
  if mode == true then
    
    local file = io.open(inputpath, "rb")
    if not file then
      return false, "Cannot open file"
    end
    local outfile = io.open(outputpath, "wb")
    if not outfile then
      file:close()
      return false, "Cannot create output file"
    end
    
    local data_size = file:seek("end")
    file:seek("set", 0)
    
    local salt
    if not settings.salt_seed then
      salt = lib.random(32)
    else
      salt = {}
      local salt_hash
      salt_hash = crypto.hmac( crypto.sha512, "salt", settings.salt_seed )
      for i = 1, 64, 2 do
        local hex_pair = string.sub(salt_hash, i, i + 1)
        
        if #hex_pair == 2 then
          table.insert(salt, string.char(tonumber(hex_pair, 16)))
        end
      end
      salt = table.concat(salt)
    end
    outfile:write(salt)
    
    -- header
    local header = {}
    -- magic bytes
    table.insert( header, "C" )
    table.insert( header, "R" )
    table.insert( header, "P" )
    -- version
    table.insert( header, string.char(math.floor(crypter_version / 256)) )
    table.insert( header, string.char(crypter_version % 256) )
    -- I_N
    local I_N = 9 --default 256000 iterations
    if settings.key_iterations and not( (tonumber(settings.key_iterations) ~= nil and tonumber(settings.key_iterations) <= 255) ) then
      if string.sub(settings.key_iterations, -1) == "k" then
        settings.key_iterations = string.gsub(settings.key_iterations, "k", "000")
      end
      I_N = 1
      for exmpl, value in pairs(I_N_for_K_I) do
        if tonumber(exmpl) < tonumber(settings.key_iterations) and (value + 1) > I_N then
          I_N = value + 1
        end
      end
    elseif tonumber(settings.key_iterations) ~= nil and tonumber(settings.key_iterations) <= 255 then
      I_N = tonumber(settings.key_iterations)
    end
    table.insert( header, string.char(I_N) )
    -- C_P
    local C_P
    if settings.chunk_size == nil then
      C_P = 13 --default 8kb or 8192 bytes
    else
      if tonumber(settings.chunk_size) and tonumber(settings.chunk_size) > 0 and tonumber(settings.chunk_size) <= 255 then
        C_P = tonumber(settings.chunk_size)
      elseif string.sub(settings.chunk_size, -2) == "kb" then
        C_P = math.ceil(math.log(tonumber(string.sub(settings.chunk_size, 1, #settings.chunk_size - 2)) * 1024, 2))
      elseif string.sub(settings.chunk_size, -2) == "mb" then
        C_P = math.ceil(math.log(tonumber(string.sub(settings.chunk_size, 1, #settings.chunk_size - 2)) * 1024 * 1024, 2))
      elseif string.sub(settings.chunk_size, -2) == "gb" then
        C_P = math.ceil(math.log(tonumber(string.sub(settings.chunk_size, 1, #settings.chunk_size - 2)) * 1024 * 1024 * 1024, 2))
      elseif string.sub(settings.chunk_size, -1) == "b" then
        C_P = math.ceil(math.log(tonumber(string.sub(settings.chunk_size, 1, #settings.chunk_size - 1)), 2))
      end
      if C_P > 255 then
        C_P = 13
      end
    end
    table.insert( header, string.char(C_P) )
    
    for i = 1, 32 - #header do
      table.insert( header, string.char(0) )
    end
    header = table.concat(header)
    
    local header_crypted = {}
    local hash_noise = crypto.hmac( crypto.sha512, "header", salt)
    for i = 1, #header do
      local noise = tonumber(string.sub(hash_noise, i*2-1, i*2), 16)
      header_crypted[i] = string.char((string.byte(header, i) + noise) % 256)
    end
    header_crypted = table.concat(header_crypted)
    
    outfile:write(header_crypted)
    
    if I_N > 0 then
      for i = 1, 500 * ( 2 ^ I_N ) do --"500 * ( 2 ^ I_N )" = key_iterations
        key = crypto.hmac(crypto.sha512, key, salt .. i)
      end
    end
    
    local prk = crypto.hmac(crypto.sha512, salt, key)
    local enc_key = crypto.hmac(crypto.sha512, prk, "enc")
    local mac_key = crypto.hmac(crypto.sha512, prk, "mac")
    
    local rolling_hash = crypto.hmac( crypto.sha512, salt, mac_key )
    local rolling_noise = crypto.hmac(crypto.sha512, "noise", enc_key)
    
    local chunk_size = 2^C_P
    local chunk_num = 1
    while true do
      local chunk = file:read(chunk_size)
      if not chunk then break end
      
      local hash_noise = {}
      for i = 1, math.ceil(#chunk / 64) do
        rolling_noise = crypto.hmac(crypto.sha512, rolling_noise .. ":" .. chunk_num .. ":" .. i .. ":" .. data_size .. ":" .. salt, enc_key)
        table.insert(hash_noise, rolling_noise )
      end
      hash_noise = table.concat(hash_noise)
      
      local modified_byte_chunk = {}
      
      for i = 1, #chunk do
        local noise = tonumber(string.sub(hash_noise, i*2-1, i*2), 16)
        modified_byte_chunk[i] = string.char((string.byte(chunk, i) + noise) % 256)
      end
      modified_byte_chunk = table.concat(modified_byte_chunk)
      
      outfile:write(modified_byte_chunk)
      rolling_hash = crypto.hmac( crypto.sha512, modified_byte_chunk, rolling_hash )
      
      chunk_num = chunk_num + 1
    end
    
    local file_hash = {}
    for i = 1, 128, 2 do
      local hex_pair = string.sub(rolling_hash, i, i + 1)
      
      if #hex_pair == 2 then
        table.insert(file_hash, string.char(tonumber(hex_pair, 16)))
      end
    end
    file_hash = table.concat(file_hash)
    outfile:write(file_hash)
    
    file:close()
    outfile:close()
    return true
  else
    
    local file = io.open(inputpath, "rb")
    if not file then
      return false, "Cannot open file"
    end
    
    local file_size = file:seek("end")
    local data_size = file_size -32 -32 -64
    local encrypted_data_size = data_size
    
    if encrypted_data_size < 0 then
      file:close()
      return false, "File is corrupted"
    end
    
    file:seek("end", -64)
    local file_hash = file:read(64)
    
    file:seek("set", 0)
    
    local salt = file:read(32)
    local header_crypted = file:read(32)
    
    local header = {}
    local hash_noise = crypto.hmac( crypto.sha512, "header", salt)
    for i = 1, #header_crypted do
      local noise = tonumber(string.sub(hash_noise, i*2-1, i*2), 16)
      header[i] = string.char((string.byte(header_crypted, i) - noise) % 256)
    end
    header = table.concat(header)
    
    if string.sub(header, 1, 3) ~= "CRP" then
      file:close()
      return false, "Incorrect file type"
    end
    
    local file_crypter_version = string.byte(header, 4)*256 + string.byte(header, 5)
    if crypter_version ~= file_crypter_version then
      file:close()
      return false, "File cryption version '" .. file_crypter_version .. "' is different from version '" .. crypter_version .. "' of the cryptor"
    end
    
    local I_N = string.byte(header, 6)
    if I_N > 0 then
      for i = 1, 500 * ( 2 ^ I_N ) do
        key = crypto.hmac(crypto.sha512, key, salt .. i)
      end
    end
    
    local C_P = string.byte(header, 7)
    local chunk_size = 2^C_P
    
    local prk = crypto.hmac(crypto.sha512, salt, key)
    local enc_key = crypto.hmac(crypto.sha512, prk, "enc")
    local mac_key = crypto.hmac(crypto.sha512, prk, "mac")
    
    local rolling_hash = crypto.hmac( crypto.sha512, salt, mac_key )
    local bytes_read = 0
    
    while bytes_read < encrypted_data_size do
      local current_chunk_size = chunk_size
      if (encrypted_data_size - bytes_read) < chunk_size then
        current_chunk_size = encrypted_data_size - bytes_read
      end
      
      local chunk = file:read(current_chunk_size)
      if not chunk then break end
      bytes_read = bytes_read + #chunk
      
      rolling_hash = crypto.hmac(crypto.sha512, chunk, rolling_hash)
    end
    
    local calculated_file_hash = {}
    for i = 1, 128, 2 do
      local hex_pair = string.sub(rolling_hash, i, i + 1)
      if #hex_pair == 2 then
        table.insert(calculated_file_hash, string.char(tonumber(hex_pair, 16)))
      end
    end
    calculated_file_hash = table.concat(calculated_file_hash)
    
    if not lib.constime_compare(file_hash, calculated_file_hash) then
      file:close()
      return false, "Incorrect key or file is corrupted"
    end
    
    local outfile = io.open(outputpath, "wb")
    if not outfile then
      file:close()
      return false, "Cannot create output file"
    end
    
    file:seek("set", 64)
    
    local rolling_noise = crypto.hmac(crypto.sha512, "noise", enc_key)
    
    local chunk_num = 1
    bytes_read = 0
    
    while bytes_read < encrypted_data_size do
      local current_chunk_size = chunk_size
      if (encrypted_data_size - bytes_read) < chunk_size then
        current_chunk_size = encrypted_data_size - bytes_read
      end
      
      local chunk = file:read(current_chunk_size)
      if not chunk then break end
      bytes_read = bytes_read + #chunk
      
      local hash_noise = {}
      for i = 1, math.ceil(#chunk / 64) do
        rolling_noise = crypto.hmac(crypto.sha512, rolling_noise .. ":" .. chunk_num .. ":" .. i .. ":" .. data_size .. ":" .. salt, enc_key)
        table.insert(hash_noise, rolling_noise )
      end
      hash_noise = table.concat(hash_noise)
      
      local decrypted_byte_chunk = {}
      for i = 1, #chunk do
        local noise = tonumber(string.sub(hash_noise, i*2-1, i*2), 16)
        decrypted_byte_chunk[i] = string.char((string.byte(chunk, i) - noise) % 256)
      end
      
      outfile:write(table.concat(decrypted_byte_chunk))
      chunk_num = chunk_num + 1
    end
    
    file:close()
    outfile:close()
    return true
  end
  
  return false
end

return lib
