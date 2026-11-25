# frozen_string_literal: true

# Ruby (Onigmo) measurement worker.
#
# Protocol: one JSON object per line on stdin, one JSON object per line on
# stdout.  Wall-clock enforcement is the parent's job; Ruby 3.1 has no
# Regexp.timeout, and a stuck match cannot be interrupted safely in-process.

require 'json'

$stdout.sync = true

FLAGS = {
  'i' => Regexp::IGNORECASE,
  's' => Regexp::MULTILINE,   # in Ruby /m means "dot matches newline"
  'x' => Regexp::EXTENDED
}.freeze

def compile(pattern, flags)
  options = 0
  flags.to_s.each_char { |ch| options |= FLAGS.fetch(ch, 0) }
  Regexp.new(pattern, options)
end

cache = {}
engine = defined?(RubyVM::YJIT) || true
version = RUBY_VERSION
onig = defined?(Regexp::VERSION) ? Regexp::VERSION : nil

STDIN.each_line do |line|
  line = line.strip
  next if line.empty?

  begin
    request = JSON.parse(line)
  rescue StandardError => e
    puts JSON.generate({ 'status' => 'error', 'error' => "bad request: #{e.class}" })
    next
  end

  pattern = request['pattern'].to_s
  flags = request['flags'].to_s
  response = { 'engine' => 'ruby-onigmo', 'engine_version' => version }
  response['onigmo_version'] = onig if onig

  begin
    key = [pattern, flags]
    compiled = cache[key]
    if compiled.nil?
      compiled = compile(pattern, flags)
      cache[key] = compiled if cache.size < 128
    end
    if request['warmup']
      response['status'] = 'ok'
      puts JSON.generate(response)
      next
    end

    text = request['text'].to_s
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    compiled.match?(text)
    elapsed = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000.0
    response['status'] = 'completed'
    response['elapsed_ms'] = elapsed
  rescue RegexpError => e
    response['status'] = 'error'
    response['error'] = "RegexpError: #{e.message}"
  rescue StandardError => e
    response['status'] = 'error'
    response['error'] = "#{e.class}: #{e.message}"
  end

  puts JSON.generate(response)
end
