/*
  Warnings:

  - You are about to drop the column `duration` on the `courses` table. All the data in the column will be lost.
  - You are about to drop the column `featured` on the `courses` table. All the data in the column will be lost.
  - You are about to drop the column `instructor` on the `courses` table. All the data in the column will be lost.
  - You are about to drop the column `learning_path` on the `courses` table. All the data in the column will be lost.
  - You are about to drop the column `prerequisites` on the `courses` table. All the data in the column will be lost.
  - You are about to drop the column `token` on the `courses` table. All the data in the column will be lost.
  - You are about to drop the column `time_spent` on the `lesson_progress` table. All the data in the column will be lost.
  - You are about to drop the column `duration` on the `lessons` table. All the data in the column will be lost.
  - You are about to drop the column `course_id` on the `payments` table. All the data in the column will be lost.
  - You are about to drop the column `razorpay_order_id` on the `payments` table. All the data in the column will be lost.
  - You are about to drop the column `razorpay_payment_id` on the `payments` table. All the data in the column will be lost.
  - You are about to drop the column `razorpay_signature` on the `payments` table. All the data in the column will be lost.
  - You are about to drop the column `user_purchase_id` on the `payments` table. All the data in the column will be lost.
  - You are about to drop the column `helpful` on the `reviews` table. All the data in the column will be lost.
  - You are about to drop the `user_profiles` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `user_purchases` table. If the table is not empty, all the data it contains will be lost.
  - A unique constraint covering the columns `[provider_payment_id]` on the table `payments` will be added. If there are existing duplicate values, this will fail.
  - Made the column `mentor_id` on table `courses` required. This step will fail if there are existing NULL values in that column.
  - Added the required column `provider_payment_id` to the `payments` table without a default value. This is not possible if the table is not empty.
  - Added the required column `purchase_id` to the `payments` table without a default value. This is not possible if the table is not empty.

*/
-- DropForeignKey
ALTER TABLE "public"."admin_actions" DROP CONSTRAINT "admin_actions_admin_id_fkey";

-- DropForeignKey
ALTER TABLE "public"."courses" DROP CONSTRAINT "courses_mentor_id_fkey";

-- DropForeignKey
ALTER TABLE "public"."enrollments" DROP CONSTRAINT "enrollments_user_id_fkey";

-- DropForeignKey
ALTER TABLE "public"."payments" DROP CONSTRAINT "payments_course_id_fkey";

-- DropForeignKey
ALTER TABLE "public"."payments" DROP CONSTRAINT "payments_user_purchase_id_fkey";

-- DropForeignKey
ALTER TABLE "public"."reviews" DROP CONSTRAINT "reviews_user_id_fkey";

-- DropForeignKey
ALTER TABLE "public"."user_purchases" DROP CONSTRAINT "user_purchases_course_id_fkey";

-- DropForeignKey
ALTER TABLE "public"."user_purchases" DROP CONSTRAINT "user_purchases_user_id_fkey";

-- DropIndex
DROP INDEX "public"."payments_razorpay_payment_id_key";

-- AlterTable
ALTER TABLE "public"."course_tags" ALTER COLUMN "color" DROP NOT NULL;

-- AlterTable
ALTER TABLE "public"."courses" DROP COLUMN "duration",
DROP COLUMN "featured",
DROP COLUMN "instructor",
DROP COLUMN "learning_path",
DROP COLUMN "prerequisites",
DROP COLUMN "token",
ADD COLUMN     "duration_hours" INTEGER,
ADD COLUMN     "is_featured" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "learning_path_id" TEXT,
ADD COLUMN     "rating_average" DECIMAL(3,2) NOT NULL DEFAULT 0,
ADD COLUMN     "review_count" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "token_price" INTEGER,
ALTER COLUMN "mentor_id" SET NOT NULL;

-- AlterTable
ALTER TABLE "public"."lesson_progress" DROP COLUMN "time_spent",
ADD COLUMN     "time_spent_min" INTEGER;

-- AlterTable
ALTER TABLE "public"."lessons" DROP COLUMN "duration",
ADD COLUMN     "duration_min" INTEGER;

-- AlterTable
ALTER TABLE "public"."payments" DROP COLUMN "course_id",
DROP COLUMN "razorpay_order_id",
DROP COLUMN "razorpay_payment_id",
DROP COLUMN "razorpay_signature",
DROP COLUMN "user_purchase_id",
ADD COLUMN     "provider" TEXT NOT NULL DEFAULT 'razorpay',
ADD COLUMN     "provider_order_id" TEXT,
ADD COLUMN     "provider_payment_id" TEXT NOT NULL,
ADD COLUMN     "purchase_id" TEXT NOT NULL,
ADD COLUMN     "signature" TEXT;

-- AlterTable
ALTER TABLE "public"."reviews" DROP COLUMN "helpful";

-- DropTable
DROP TABLE "public"."user_profiles";

-- DropTable
DROP TABLE "public"."user_purchases";

-- CreateTable
CREATE TABLE "public"."User" (
    "id" TEXT NOT NULL,
    "full_name" TEXT,
    "email" TEXT,
    "email_verified" TIMESTAMP(3),
    "image" TEXT,
    "bio" TEXT,
    "user_type" "public"."user_type" NOT NULL DEFAULT 'STUDENT',
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."accounts" (
    "id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "provider_account_id" TEXT NOT NULL,
    "refresh_token" TEXT,
    "access_token" TEXT,
    "expires_at" INTEGER,
    "token_type" TEXT,
    "scope" TEXT,
    "id_token" TEXT,
    "session_state" TEXT,

    CONSTRAINT "accounts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."sessions" (
    "id" TEXT NOT NULL,
    "session_token" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "expires" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "sessions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."verification_tokens" (
    "identifier" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "expires" TIMESTAMP(3) NOT NULL
);

-- CreateTable
CREATE TABLE "public"."learning_paths" (
    "id" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT,

    CONSTRAINT "learning_paths_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."course_prerequisites" (
    "course_id" TEXT NOT NULL,
    "prerequisite_id" TEXT NOT NULL,

    CONSTRAINT "course_prerequisites_pkey" PRIMARY KEY ("course_id","prerequisite_id")
);

-- CreateTable
CREATE TABLE "public"."bundles" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "price" DECIMAL(10,2) NOT NULL,
    "image_url" TEXT,
    "is_active" BOOLEAN NOT NULL DEFAULT true,

    CONSTRAINT "bundles_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."course_bundles" (
    "course_id" TEXT NOT NULL,
    "bundle_id" TEXT NOT NULL,

    CONSTRAINT "course_bundles_pkey" PRIMARY KEY ("course_id","bundle_id")
);

-- CreateTable
CREATE TABLE "public"."purchases" (
    "id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "total_amount" DECIMAL(10,2) NOT NULL,
    "purchased_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "status" "public"."payment_status" NOT NULL DEFAULT 'PENDING',

    CONSTRAINT "purchases_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."purchase_items" (
    "id" TEXT NOT NULL,
    "purchase_id" TEXT NOT NULL,
    "purchase_price" DECIMAL(10,2) NOT NULL,
    "course_id" TEXT,
    "bundle_id" TEXT,

    CONSTRAINT "purchase_items_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."certificates" (
    "id" TEXT NOT NULL,
    "enrollment_id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "course_name" TEXT NOT NULL,
    "issued_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "credential_url" TEXT NOT NULL,

    CONSTRAINT "certificates_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."discussion_threads" (
    "id" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "content" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "lesson_id" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "discussion_threads_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."discussion_posts" (
    "id" TEXT NOT NULL,
    "content" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "thread_id" TEXT NOT NULL,
    "parent_id" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "discussion_posts_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "public"."User"("email");

-- CreateIndex
CREATE UNIQUE INDEX "accounts_provider_provider_account_id_key" ON "public"."accounts"("provider", "provider_account_id");

-- CreateIndex
CREATE UNIQUE INDEX "sessions_session_token_key" ON "public"."sessions"("session_token");

-- CreateIndex
CREATE UNIQUE INDEX "verification_tokens_token_key" ON "public"."verification_tokens"("token");

-- CreateIndex
CREATE UNIQUE INDEX "verification_tokens_identifier_token_key" ON "public"."verification_tokens"("identifier", "token");

-- CreateIndex
CREATE INDEX "purchases_user_id_idx" ON "public"."purchases"("user_id");

-- CreateIndex
CREATE UNIQUE INDEX "certificates_enrollment_id_key" ON "public"."certificates"("enrollment_id");

-- CreateIndex
CREATE UNIQUE INDEX "certificates_credential_url_key" ON "public"."certificates"("credential_url");

-- CreateIndex
CREATE INDEX "certificates_user_id_idx" ON "public"."certificates"("user_id");

-- CreateIndex
CREATE INDEX "courses_mentor_id_idx" ON "public"."courses"("mentor_id");

-- CreateIndex
CREATE INDEX "lessons_course_id_idx" ON "public"."lessons"("course_id");

-- CreateIndex
CREATE UNIQUE INDEX "payments_provider_payment_id_key" ON "public"."payments"("provider_payment_id");

-- CreateIndex
CREATE INDEX "payments_purchase_id_idx" ON "public"."payments"("purchase_id");

-- AddForeignKey
ALTER TABLE "public"."accounts" ADD CONSTRAINT "accounts_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."sessions" ADD CONSTRAINT "sessions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."courses" ADD CONSTRAINT "courses_mentor_id_fkey" FOREIGN KEY ("mentor_id") REFERENCES "public"."User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."courses" ADD CONSTRAINT "courses_learning_path_id_fkey" FOREIGN KEY ("learning_path_id") REFERENCES "public"."learning_paths"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."course_prerequisites" ADD CONSTRAINT "course_prerequisites_course_id_fkey" FOREIGN KEY ("course_id") REFERENCES "public"."courses"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."course_prerequisites" ADD CONSTRAINT "course_prerequisites_prerequisite_id_fkey" FOREIGN KEY ("prerequisite_id") REFERENCES "public"."courses"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."course_bundles" ADD CONSTRAINT "course_bundles_course_id_fkey" FOREIGN KEY ("course_id") REFERENCES "public"."courses"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."course_bundles" ADD CONSTRAINT "course_bundles_bundle_id_fkey" FOREIGN KEY ("bundle_id") REFERENCES "public"."bundles"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."purchases" ADD CONSTRAINT "purchases_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."purchase_items" ADD CONSTRAINT "purchase_items_purchase_id_fkey" FOREIGN KEY ("purchase_id") REFERENCES "public"."purchases"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."purchase_items" ADD CONSTRAINT "purchase_items_course_id_fkey" FOREIGN KEY ("course_id") REFERENCES "public"."courses"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."purchase_items" ADD CONSTRAINT "purchase_items_bundle_id_fkey" FOREIGN KEY ("bundle_id") REFERENCES "public"."bundles"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."payments" ADD CONSTRAINT "payments_purchase_id_fkey" FOREIGN KEY ("purchase_id") REFERENCES "public"."purchases"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."enrollments" ADD CONSTRAINT "enrollments_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."certificates" ADD CONSTRAINT "certificates_enrollment_id_fkey" FOREIGN KEY ("enrollment_id") REFERENCES "public"."enrollments"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."certificates" ADD CONSTRAINT "certificates_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."reviews" ADD CONSTRAINT "reviews_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."discussion_threads" ADD CONSTRAINT "discussion_threads_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."discussion_threads" ADD CONSTRAINT "discussion_threads_lesson_id_fkey" FOREIGN KEY ("lesson_id") REFERENCES "public"."lessons"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."discussion_posts" ADD CONSTRAINT "discussion_posts_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."discussion_posts" ADD CONSTRAINT "discussion_posts_thread_id_fkey" FOREIGN KEY ("thread_id") REFERENCES "public"."discussion_threads"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."discussion_posts" ADD CONSTRAINT "discussion_posts_parent_id_fkey" FOREIGN KEY ("parent_id") REFERENCES "public"."discussion_posts"("id") ON DELETE NO ACTION ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."admin_actions" ADD CONSTRAINT "admin_actions_admin_id_fkey" FOREIGN KEY ("admin_id") REFERENCES "public"."User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."notifications" ADD CONSTRAINT "notifications_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
