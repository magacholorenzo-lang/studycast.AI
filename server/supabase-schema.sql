-- Studycast AI - schema do Supabase
-- Rode isso uma vez no SQL Editor do Supabase (Project -> SQL Editor -> New query -> Run)

create table if not exists users (
  id bigint primary key,
  name text not null,
  email text not null unique,
  password_hash text not null,
  plan text not null default 'free',
  study_minutes integer not null default 0,
  is_admin boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists materials (
  id bigint primary key,
  user_id bigint not null references users(id) on delete cascade,
  title text not null,
  type text,
  goal text,
  date timestamptz not null default now(),
  source_text text,
  resumo jsonb not null default '[]',
  flashcards jsonb not null default '[]',
  mindmap jsonb not null default '[]',
  explanation text
);
create index if not exists materials_user_id_idx on materials(user_id);

create table if not exists quizzes (
  id bigint primary key,
  user_id bigint not null references users(id) on delete cascade,
  material_id bigint,
  material_title text,
  mode text not null,
  difficulty text,
  count integer,
  questions jsonb not null default '[]',
  answers jsonb,
  results jsonb,
  status text not null default 'pending',
  date timestamptz not null default now()
);
create index if not exists quizzes_user_id_idx on quizzes(user_id);

create table if not exists feedback (
  id bigint primary key,
  name text,
  rating integer,
  message text not null,
  date timestamptz not null default now()
);
