# frozen_string_literal: true

# Extracts regexp literals and Regexp constructor calls from a Ruby source file
# using Ripper (available in every MRI since 1.9) and prints JSON on stdout.
#
# Usage: ruby ruby_extract.rb path/to/file.rb < path/to/file.rb
# Output: {"ok":true,"regexes":[{line,column,function,pattern,flags,source_type,...}]}

require 'ripper'
require 'json'

filename = ARGV[0] || '(stdin)'
source = STDIN.read
sexp = begin
  Ripper.sexp(source)
rescue StandardError
  nil
end

unless sexp
  puts JSON.generate({ 'ok' => false, 'error' => 'ripper could not parse the file', 'regexes' => [] })
  exit 0
end

results = []
seen = {}
depth_limit = 400

def pos_of(token)
  return nil unless token.is_a?(Array) && token[0].to_s.start_with?('@')
  token[2]
end

def ident_name(node)
  return nil unless node.is_a?(Array)
  return node[1] if node[0] == :@ident || node[0] == :@const
  nil
end

def method_name(node)
  return nil unless node.is_a?(Array)
  case node[0]
  when :call
    ident_name(node[3])
  when :fcall, :vcall, :command
    ident_name(node[1])
  when :command_call
    ident_name(node[3])
  when :method_add_arg
    method_name(node[1])
  when :method_add_block
    method_name(node[1])
  else
    nil
  end
end

def receiver_const(node)
  return nil unless node.is_a?(Array) && node[0] == :call
  receiver = node[1]
  if receiver.is_a?(Array) && receiver[0] == :var_ref && receiver[1].is_a?(Array) &&
     receiver[1][0] == :@const
    return receiver[1][1]
  end
  nil
end

def literal_parts(node)
  # node is the parts list of :regexp_literal
  parts = []
  dynamic = false
  Array(node).each do |part|
    if part.is_a?(Array) && part[0] == :@tstring_content
      parts << part[1]
    elsif part.is_a?(Array) && part[0] == :string_content
      Array(part[1..]).each do |inner|
        if inner.is_a?(Array) && inner[0] == :@tstring_content
          parts << inner[1]
        else
          dynamic = true
        end
      end
    elsif part.is_a?(Array) && part[0] == :string_embexpr
      dynamic = true
    end
  end
  [parts.join, dynamic]
end

def string_literal_value(node)
  return nil unless node.is_a?(Array) && node[0] == :string_literal
  content = node[1]
  return '' unless content
  return nil unless content[0] == :string_content
  value = +''
  Array(content[1..]).each do |part|
    return nil unless part.is_a?(Array) && part[0] == :@tstring_content
    value << part[1]
  end
  value
end

def record(results, seen, line, column, function, pattern, flags, source_type, note)
  return unless line
  key = [line, column, pattern, function]
  return if seen[key]
  seen[key] = true
  results << {
    'line' => line,
    'column' => column,
    'function' => function,
    'pattern' => pattern,
    'flags' => flags,
    'source_type' => source_type,
    'notes' => note ? [note] : []
  }
end

def emit_literal(node, function, results, seen)
  parts = node[1]
  ending = node[2]
  pattern, dynamic = literal_parts(parts)
  pos = pos_of(ending)
  line = pos && pos[0]
  column = pos && pos[1] ? pos[1] + 1 : nil
  suffix = ending.is_a?(Array) && ending[1].is_a?(String) ? ending[1] : ''
  flags = suffix.sub(/\A[^a-z]*/, '').downcase
  if dynamic
    record(results, seen, line, column, function, nil, flags, 'dynamic',
           'regexp built with string interpolation')
  else
    record(results, seen, line, column, function, pattern, flags, 'literal', nil)
  end
end

walker = lambda do |node, function, depth|
  next if depth > depth_limit
  next unless node.is_a?(Array)

  case node[0]
  when :regexp_literal
    emit_literal(node, function || 'Regexp literal', results, seen)
    next
  when :method_add_arg, :method_add_block
    name = method_name(node[1])
    walker.call(node[1], function, depth + 1)
    walker.call(node[2], name || function, depth + 1)
    # method_add_block: node[2] is the block, node[1] holds call+args
    next
  when :command
    name = method_name(node)
    walker.call(node[2], name || function, depth + 1)
    next
  when :command_call
    name = method_name(node)
    walker.call(node[1], function, depth + 1)
    walker.call(node[4], name || function, depth + 1)
    next
  when :binary
    if node[2] == :=~ || node[2] == :!~
      walker.call(node[1], function, depth + 1)
      walker.call(node[3], '=~', depth + 1)
      next
    end
  when :call
    const = receiver_const(node)
    name = ident_name(node[3])
    if const == 'Regexp' && (name == 'new' || name == 'compile')
      # handled by the enclosing method_add_arg; nothing to do here
      next
    end
  when :method_add_arg
    nil
  end

  node.each { |child| walker.call(child, function, depth + 1) }
end

# Regexp.new / Regexp.compile need the surrounding call node (receiver + args).
handle_constructor = lambda do |node, depth|
  next if depth > depth_limit
  next unless node.is_a?(Array)

  if node[0] == :method_add_arg || node[0] == :method_add_block
    call = node[1]
    if call.is_a?(Array) && call[0] == :call && receiver_const(call) == 'Regexp' &&
       %w[new compile].include?(ident_name(call[3]))
      args_node = node[2]
      args = extract_args(args_node)
      first = args[0]
      pos = call[3].is_a?(Array) ? call[3][2] : nil
      line = pos && pos[0]
      column = pos && pos[1] ? pos[1] + 1 : nil
      if first
        value = string_literal_value(first)
        flags = ''
        if args[1]
          flags = regexp_options(args[1])
        end
        if value.nil?
          record(results, seen, line, column, 'Regexp.new', nil, flags, 'dynamic',
                 'pattern argument is not a string literal')
        else
          record(results, seen, line, column, 'Regexp.new', value, flags, 'literal', nil)
        end
      end
    end
  end
  node.each { |child| handle_constructor.call(child, depth + 1) }
end

def extract_args(node)
  return [] unless node.is_a?(Array)
  if node[0] == :arg_paren
    inner = node[1]
    if inner.is_a?(Array) && inner[0] == :args_add_block
      return Array(inner[1])
    end
    return inner.is_a?(Array) ? [inner] : []
  end
  return Array(node[1]) if node[0] == :args_add_block
  [node]
end

def regexp_options(node)
  flags = +''
  walk = lambda do |item|
    next unless item.is_a?(Array)
    if item[0] == :const_path_ref
      const = item[2].is_a?(Array) ? item[2][1] : nil
      case const
      when 'IGNORECASE' then flags << 'i'
      when 'EXTENDED' then flags << 'x'
      when 'MULTILINE' then flags << 'm'
      end
    elsif item[0] == :binary
      walk.call(item[1])
      walk.call(item[3])
    elsif item[0] == :int
      value = item[1].to_i
      flags << 'i' if value & 1 != 0
      flags << 'x' if value & 2 != 0
      flags << 'm' if value & 4 != 0
    end
  end
  walk.call(node)
  flags
end

walker.call(sexp, nil, 0)
handle_constructor.call(sexp, 0)

puts JSON.generate({ 'ok' => true, 'regexes' => results })
