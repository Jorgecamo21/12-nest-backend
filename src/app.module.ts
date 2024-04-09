import { Module } from '@nestjs/common'; 
import { ConfigModule } from '@nestjs/config'; 
import { AuthModule } from './auth/auth.module';
import { MongooseModule } from '@nestjs/mongoose';

@Module({
  imports: [
    AuthModule,
    ConfigModule.forRoot(),
    MongooseModule.forRoot(process.env.MONGO_URL)
  ],
  controllers: [],
  providers: [],
})
export class AppModule {

}
