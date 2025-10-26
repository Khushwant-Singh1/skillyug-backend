#!/usr/bin/env tsx

import { PDFExtractor } from './src/utils/pdf/extractor';
import { CourseRecord } from './src/types/recommendation.types';

async function testPDFExtraction() {
  console.log('🧪 Testing PDF extraction...');
  
  const pdfPath = '/home/anuragisinsane/skillyug/Python Beginner – ₹1299 🎯 30% refund via scholarship test 🎟 20 tokens (missed class buyback) 🚀 2 bootcamps (30% OFF) 🏆 Certificate of completion Bounder (Beginner → Intermediate) – ₹1899 🎯 50 (3).pdf';
  const outputPath = '/home/anuragisinsane/skillyug/Backend/data/catalog/courses.json';
  
  try {
    const extractor = new PDFExtractor(pdfPath);
    const courses = await extractor.extractCourses();
    
    console.log('📚 Extracted courses:');
    courses.forEach((course: CourseRecord, index: number) => {
      console.log(`${index + 1}. ${course.title} - ₹${course.price}`);
      console.log(`   Level: ${course.level}, Topics: ${course.topics.join(', ')}`);
      console.log(`   Perks: ${course.perks.join(', ')}`);
      console.log('');
    });
    
    await extractor.saveCatalog(courses, outputPath);
    console.log('✅ PDF extraction test completed successfully!');
    
  } catch (error) {
    console.error('❌ PDF extraction failed:', error);
    process.exit(1);
  }
}

testPDFExtraction();