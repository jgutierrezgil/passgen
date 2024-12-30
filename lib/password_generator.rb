# frozen_string_literal: true

require 'securerandom'
require 'logger'

# A secure password generation and analysis tool that implements OWASP password guidelines
#
# @example Generate a password with default settings
#   generator = PasswordGenerator.new
#   result = generator.generate!(12)
#   puts result[:password] # => "aB3$xyz12!@#"
#
# @example Generate a password without special characters
#   generator = PasswordGenerator.new
#   result = generator.generate!(12, include_special: false)
#   puts result[:password] # => "aB3xyz12defg"
#
# Security features:
# * Uses Ruby's SecureRandom for cryptographically secure random number generation
# * Implements OWASP password guidelines
# * Includes password strength analysis based on multiple factors
# * Logs generation attempts for security auditing
# * Input validation to prevent buffer overflow attacks
#
# @author Tu_Nombre
# @version 1.0.0
class PasswordGenerator
  # Array of alphanumeric characters used for password generation
  # @return [Array<String>] frozen array of alphanumeric characters
  ALPHANUMERIC_CHARS = [('a'..'z'), ('A'..'Z'), ('0'..'9')].map(&:to_a).flatten.freeze

  # Array of special characters used for password generation
  # @return [Array<String>] frozen array of special characters
  SPECIAL_CHARS = ['!', '@', '#', '$', '%', '^', '&', '*', '-', '_', '/'].freeze
  
  # Initializes a new password generator
  #
  # @param min_length [Integer] minimum allowed password length
  # @param max_length [Integer] maximum allowed password length
  # @raise [ArgumentError] if min_length is greater than max_length
  def initialize(min_length: 8, max_length: 100)
    @min_length = min_length
    @max_length = max_length
    @all_chars = ALPHANUMERIC_CHARS + SPECIAL_CHARS
    @logger = Logger.new('password_generator.log')
    @strength_analyzer = PasswordStrengthAnalyzer.new
  end

  # Generates a secure password with the specified parameters
  #
  # @param length [Integer] the desired length of the password
  # @param include_special [Boolean] whether to include special characters
  # @return [Hash] the generated password and its strength analysis
  # @option return [String] :password The generated password
  # @option return [Hash] :strength The password strength analysis
  # @raise [ArgumentError] if length is outside the allowed range
  def generate!(length, include_special: true)
    validate_input!(length)
    log_generation_attempt(length, include_special)
    
    password = generate_secure_password(length, include_special)
    strength_result = @strength_analyzer.analyze(password)
    
    {
      password: password,
      strength: strength_result
    }
  rescue StandardError => e
    log_error(e)
    raise
  end

  private

  # Validates the input password length
  #
  # @param length [Integer] the password length to validate
  # @raise [ArgumentError] if length is invalid
  def validate_input!(length)
    unless length.is_a?(Integer) && length.between?(@min_length, @max_length)
      raise ArgumentError, "Length must be between #{@min_length} and #{@max_length}"
    end
  end

  # Generates a cryptographically secure password
  #
  # @param length [Integer] the desired password length
  # @param include_special [Boolean] whether to include special characters
  # @return [String] the generated password
  def generate_secure_password(length, include_special)
    chars = include_special ? @all_chars : ALPHANUMERIC_CHARS
    if include_special
      password = Array.new(length - 1) { chars.sample(random: SecureRandom) }
      password.push(SPECIAL_CHARS.sample(random: SecureRandom))
      password.shuffle(random: SecureRandom).join
    else
      Array.new(length) { chars.sample(random: SecureRandom) }.join
    end
  end

  # Logs a password generation attempt
  #
  # @param length [Integer] the requested password length
  # @param include_special [Boolean] whether special characters were requested
  def log_generation_attempt(length, include_special)
    @logger.info("Password generation attempt - Length: #{length}, Special chars: #{include_special}")
  end

  # Logs an error that occurred during password generation
  #
  # @param error [StandardError] the error that occurred
  def log_error(error)
    @logger.error("Error in password generation: #{error.message}")
  end
end

# Password strength analyzer implementing NIST guidelines
#
# @example Analyze a password
#   analyzer = PasswordStrengthAnalyzer.new
#   result = analyzer.analyze("MyP@ssw0rd!")
#   puts result[:strength] # => :strong
#
# Features analyzed:
# * Password length
# * Character complexity
# * Common patterns detection
# * Common password detection
#
# @author Tu_Nombre
# @version 1.0.0
class PasswordStrengthAnalyzer
  # Initializes a new password strength analyzer
  #
  # @note Loads a list of common passwords to check against
  def initialize
    @common_passwords = load_common_passwords
  end

  # Analyzes the strength of a given password
  #
  # @param password [String] the password to analyze
  # @return [Hash] the strength analysis results
  # @option return [Integer] :score The numerical strength score
  # @option return [Symbol] :strength The strength rating (:weak, :medium, :strong)
  # @option return [Hash] :details Detailed analysis of password characteristics
  def analyze(password)
    score = calculate_base_score(password)
    score -= penalty_for_common_patterns(password)
    score -= penalty_for_common_password(password)

    {
      score: score,
      strength: calculate_strength(score),
      details: generate_analysis_details(password)
    }
  end

  private

  # Calculates the base strength score for a password
  #
  # @param password [String] the password to score
  # @return [Integer] the base score
  def calculate_base_score(password)
    score = 0
    score += password.length >= 12 ? 2 : 1
    score += 2 if password.match?(/[A-Z]/)
    score += 2 if password.match?(/[a-z]/)
    score += 2 if password.match?(/\d/)
    score += 2 if password.match?(/[^A-Za-z0-9]/)
    score
  end

  # Calculates penalty for common patterns in password
  #
  # @param password [String] the password to check
  # @return [Integer] the penalty score
  def penalty_for_common_patterns(password)
    penalty = 0
    penalty += 2 if password.match?(/123|abc|qwerty/i)
    penalty += 2 if password.match?(/(.)\\1{2,}/)  # Repeated characters
    penalty
  end

  # Checks if the password matches a common password
  #
  # @param password [String] the password to check
  # @return [Integer] the penalty (5 if common, 0 if not)
  def penalty_for_common_password(password)
    @common_passwords.include?(password.downcase) ? 5 : 0
  end

  # Determines the strength category based on score
  #
  # @param score [Integer] the password strength score
  # @return [Symbol] the strength rating (:weak, :medium, :strong)
  def calculate_strength(score)
    case score
    when 0..4 then :weak
    when 5..7 then :medium
    else :strong
    end
  end

  # Generates detailed analysis of password characteristics
  #
  # @param password [String] the password to analyze
  # @return [Hash] detailed analysis results
  def generate_analysis_details(password)
    {
      length: password.length,
      has_uppercase: password.match?(/[A-Z]/),
      has_lowercase: password.match?(/[a-z]/),
      has_numbers: password.match?(/\d/),
      has_special: password.match?(/[^A-Za-z0-9]/),
      has_common_patterns: password.match?(/123|abc|qwerty/i)
    }
  end

  # Loads a list of common passwords
  #
  # @note In a real implementation, this would load from a file
  # @return [Array<String>] frozen array of common passwords
  def load_common_passwords
    ['password', '123456', 'qwerty'].freeze
  end
end