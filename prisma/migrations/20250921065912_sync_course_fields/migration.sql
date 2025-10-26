/*
  Warnings:

  - The values [DEVELOPMENT,DEVOPS,AI_ML,MOBILE] on the enum `category` will be removed. If these variants are still used in the database, this will fail.
  - You are about to drop the column `token_price` on the `courses` table. All the data in the column will be lost.

*/
-- AlterEnum
BEGIN;
CREATE TYPE "public"."category_new" AS ENUM ('PROGRAMMING', 'WEB_DEVELOPMENT', 'MOBILE_DEVELOPMENT', 'DATA_SCIENCE', 'ARTIFICIAL_INTELLIGENCE', 'CLOUD_COMPUTING', 'CYBERSECURITY', 'DESIGN', 'BUSINESS', 'MARKETING', 'OTHER');
ALTER TABLE "public"."courses" ALTER COLUMN "category" TYPE "public"."category_new" USING ("category"::text::"public"."category_new");
ALTER TYPE "public"."category" RENAME TO "category_old";
ALTER TYPE "public"."category_new" RENAME TO "category";
DROP TYPE "public"."category_old";
COMMIT;

-- AlterTable
ALTER TABLE "public"."courses" DROP COLUMN "token_price",
ADD COLUMN     "token" INTEGER NOT NULL DEFAULT 0;
