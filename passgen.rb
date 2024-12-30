require 'securerandom'

def generate_password(length = 12)
    SecureRandom.alphanumeric(length)
end

# Pedimos al usuario la longitud de la contraseña
puts "¿Cuántos caracteres debe tener tu contraseña?"
longitud = gets.chomp.to_i

# Comprobamos que la longitud sea un número y que sea mayor que 8
if longitud.class != Integer
    puts "Debes introducir un número"
    exit
else
    if longitud < 8
        puts "Debes introducir un número mayor que 8"
        exit
    end
end

puts "Generando contraseña..."
puts "Su contraseña es: #{generate_password(longitud)}"