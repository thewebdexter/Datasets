// scripts/build-hsts-filter.js
const fs = require('fs');
const { BloomFilter } = require('bloomfilter');

const HSTS_URL = 'https://chromium.googlesource.com/chromium/src/+/main/net/http/transport_security_state_static.json?format=TEXT';

async function generateFilter() {
  console.log('Fetching latest HSTS list...');
  
  try {
    // 1. Fetch the Base64 encoded file
    const response = await fetch(HSTS_URL);
    const base64Text = await response.text();
    
    // 2. Decode Base64 to a UTF-8 string
    const decodedText = Buffer.from(base64Text, 'base64').toString('utf-8');
    
    // 3. Strip out the // comments so we can parse the JSON
    const cleanJsonText = decodedText.replace(/^\s*\/\/.*$/gm, '');
    const data = JSON.parse(cleanJsonText);
    
    // 4. Extract just the domain names
    const domains = data.entries.map(entry => entry.name);
    console.log(`Found ${domains.length} domains.`);
    
    // 5. Initialize Bloom Filter (Targeting 0.1% error rate for ~160k items)
    // 2302660 bits (~288 KB), 10 hash functions
    const filter = new BloomFilter(2302660, 10);
    
    // 6. Add all domains to the filter
    domains.forEach(domain => filter.add(domain));
    
    // 7. Save the filter buckets to a local file
    // We convert the Int32Array buckets to a standard array for JSON serialization
    const filterData = [].slice.call(filter.buckets);
    fs.writeFileSync('hsts-bloom-filter.json', JSON.stringify(filterData));
    
    console.log('Successfully generated hsts-bloom-filter.json');
    
  } catch (error) {
    console.error('Failed to generate HSTS filter:', error);
    process.exit(1);
  }
}

generateFilter();
